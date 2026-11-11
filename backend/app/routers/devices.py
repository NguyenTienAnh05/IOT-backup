from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .. import alerts, lifecycle
from ..access import get_device_in_scope
from ..broker_admin import BrokerAdmin, get_broker_admin
from ..deps import Actor, any_user, get_db, require_roles
from ..models import Device, UserDevice

router = APIRouter(prefix="/api/devices", tags=["devices"])
admin_only = require_roles("Admin")


class DeviceCreate(BaseModel):
    # device_code đi vào topic và ACL nên chỉ cho ký tự an toàn (không '/', '+', '#', '%')
    device_code: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")
    type: Literal["tank", "pipe"]           # node bồn (đo mực nước, còi) hoặc node ống (đo lưu lượng, điều khiển bơm)
    site_id: int | None = None              # hai node cùng site phối hợp với nhau (cảnh báo, tự bật/tắt bơm)
    name: str = Field(default="", max_length=128)
    hw_version: str = Field(default="", max_length=32)


class DeviceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    device_code: str
    name: str
    type: str
    site_id: int | None
    state: str
    hw_version: str
    fw_version: str
    online: bool
    last_seen: datetime | None
    created_at: datetime


class ProvisionOut(BaseModel):
    device: DeviceOut
    mqtt_username: str
    mqtt_password: str
    note: str = "Mật khẩu chỉ hiển thị một lần này; hệ thống chỉ lưu bản băm."


class StateChange(BaseModel):
    state: Literal["Active", "Maintenance", "Decommissioned"]
    confirm: bool = False      # Decommissioned không thể hoàn tác nên bắt buộc xác nhận


class SiteAssign(BaseModel):
    site_id: int | None        # null = đưa thiết bị ra khỏi site


@router.get("", response_model=list[DeviceOut])
def list_devices(state: str | None = None, q: str | None = None,
                 type: Literal["tank", "pipe"] | None = None, site_id: int | None = None,
                 limit: int = Query(100, ge=1, le=500),
                 s: Session = Depends(get_db), actor: Actor = Depends(any_user)):
    """Danh sách thiết bị, lọc theo trạng thái, loại node, site (Operator và Viewer chỉ thấy thiết bị được gán)"""
    stmt = select(Device).order_by(Device.id).limit(limit)
    if actor.role != "Admin":       # theo phạm vi được gán
        stmt = stmt.where(Device.id.in_(select(UserDevice.device_id).where(UserDevice.user_id == actor.id)))
    if state:
        stmt = stmt.where(Device.state == state)
    if type:
        stmt = stmt.where(Device.type == type)
    if site_id is not None:
        stmt = stmt.where(Device.site_id == site_id)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(Device.device_code.like(like), Device.name.like(like)))
    return s.scalars(stmt).all()


@router.post("", response_model=DeviceOut, status_code=201)
def create_device(body: DeviceCreate, s: Session = Depends(get_db), actor: Actor = Depends(admin_only)):
    """Đăng ký thiết bị mới (trạng thái Registered), chọn loại node và site"""
    return lifecycle.create_device(s, device_code=body.device_code, name=body.name, hw_version=body.hw_version,
                                   device_type=body.type, site_id=body.site_id, actor_id=actor.id, ip=actor.ip)


@router.get("/{device_id}", response_model=DeviceOut)
def get_device(device_id: int, s: Session = Depends(get_db), actor: Actor = Depends(any_user)):
    """Chi tiết một thiết bị"""
    return get_device_in_scope(s, actor, device_id)


@router.put("/{device_id}/site", response_model=DeviceOut)
def set_device_site(device_id: int, body: SiteAssign, s: Session = Depends(get_db),
                    actor: Actor = Depends(admin_only)):
    """Đưa thiết bị vào site hoặc ra khỏi site (site_id=null); mỗi site tối đa một node bồn và một node ống"""
    dev = lifecycle.assign_site(s, device_id, body.site_id, actor_id=actor.id, ip=actor.ip)
    alerts.invalidate()         # engine đọc lại danh sách node trong site
    return dev


@router.post("/{device_id}/provision", response_model=ProvisionOut)
def provision_device(device_id: int, response: Response, s: Session = Depends(get_db),
                     broker: BrokerAdmin = Depends(get_broker_admin), actor: Actor = Depends(admin_only)):
    """Cấp credential MQTT, mật khẩu chỉ hiện một lần (Registered → Provisioned)"""
    dev, secret = lifecycle.provision(s, broker, device_id, actor_id=actor.id, ip=actor.ip)
    response.headers["Cache-Control"] = "no-store"      # không để cache lưu mật khẩu
    return ProvisionOut(device=DeviceOut.model_validate(dev), mqtt_username=dev.device_code,
                        mqtt_password=secret)


@router.patch("/{device_id}/state", response_model=DeviceOut)
def change_state(device_id: int, body: StateChange, s: Session = Depends(get_db),
                 broker: BrokerAdmin = Depends(get_broker_admin),
                 actor: Actor = Depends(require_roles("Admin", "Operator"))):
    """Chuyển sang Active, Maintenance hoặc thu hồi (Decommissioned cần confirm); Operator chỉ được Maintenance"""
    dev = get_device_in_scope(s, actor, device_id)          # 404 nếu ngoài phạm vi
    if actor.role == "Operator" and body.state != "Maintenance":
        raise HTTPException(403, "Operator chỉ được chuyển thiết bị của mình sang Maintenance")
    if body.state == "Decommissioned" and not body.confirm:
        raise HTTPException(422, "Thu hồi là không thể hoàn tác: gửi confirm=true để xác nhận")
    out = lifecycle.change_state(s, broker, dev.id, body.state, actor_id=actor.id, ip=actor.ip)
    if body.state == "Decommissioned":
        alerts.invalidate()                                 # node thu hồi không còn là đối tác trong site
    return out
