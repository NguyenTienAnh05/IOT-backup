from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from .. import device_config
from ..access import get_device_in_scope
from ..deps import Actor, get_db, require_roles
from .commands import get_publisher

router = APIRouter(prefix="/api/devices/{device_id}/config", tags=["config"])
operators = require_roles("Admin", "Operator")      # Viewer không xem và không sửa cấu hình


class ConfigUpdate(BaseModel):
    """Chỉ gửi các khóa cần đổi. 'version' (tùy chọn) là phiên bản client đang xem: lệch thì trả 409."""
    model_config = ConfigDict(extra="forbid", strict=True)
    version: int | None = None
    sample_interval_s: int | None = None
    tank_height_cm: int | float | None = None
    low_pct: int | float | None = None
    high_pct: int | float | None = None
    pump_max_run_s: int | None = None
    auto_mode: bool | None = None
    leak_flow_lpm: int | float | None = None
    leak_minutes: int | None = None


class LimitOut(BaseModel):
    type: str
    min: float | None
    max: float | None


class ConfigOut(BaseModel):
    device_id: int
    version: int
    config: dict[str, Any]
    limits: dict[str, LimitOut]
    applied_version: int | None
    sync_status: Literal["default", "unknown", "applied", "pending", "mismatch"]
    updated_at: datetime | None
    updated_by: str | None


class ConfigChangeOut(ConfigOut):
    changed: list[str]
    delivery: Literal["published", "failed", "unchanged"]


def _fix(state: dict) -> dict:
    if state["updated_at"] is not None:
        state = {**state, "updated_at": state["updated_at"].replace(tzinfo=timezone.utc)}
    return state


@router.get("", response_model=ConfigOut)
def get_config(device_id: int, s: Session = Depends(get_db), actor: Actor = Depends(operators)):
    """Cấu hình hiện tại, giới hạn từng khóa và trạng thái đồng bộ với thiết bị"""
    return _fix(device_config.get_state(s, get_device_in_scope(s, actor, device_id)))


@router.put("", response_model=ConfigChangeOut)
def put_config(device_id: int, body: ConfigUpdate, s: Session = Depends(get_db),
               publisher=Depends(get_publisher), actor: Actor = Depends(operators)):
    """Lưu cấu hình mới (version + 1) rồi publish retained. delivery=failed nghĩa là đã lưu nhưng chưa gửi được
    tới broker: dùng POST .../config/publish để gửi lại."""
    dev = get_device_in_scope(s, actor, device_id)
    updates = body.model_dump(exclude_none=True, exclude={"version"})
    state, changed, delivery = device_config.update_config(s, publisher, dev, updates, expected_version=body.version,
                                                           actor_id=actor.id, ip=actor.ip)
    return {**_fix(state), "changed": changed, "delivery": delivery}


@router.post("/publish", response_model=ConfigChangeOut)
def republish_config(device_id: int, s: Session = Depends(get_db), publisher=Depends(get_publisher),
                     actor: Actor = Depends(operators)):
    """Gửi lại cấu hình hiện tại (retained) xuống thiết bị"""
    dev = get_device_in_scope(s, actor, device_id)
    state, delivery = device_config.publish_current(s, publisher, dev, actor_id=actor.id, ip=actor.ip)
    return {**_fix(state), "changed": [], "delivery": delivery}
