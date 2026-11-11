from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from .. import alerts as engine
from ..access import get_device_in_scope
from ..audit import write_audit
from ..db import utcnow
from ..deps import Actor, any_user, get_db, require_roles
from ..events import emit
from ..lifecycle import Conflict, NotFound
from ..models import Alert, Device, User, UserDevice

router = APIRouter(prefix="/api", tags=["alerts"])
handlers = require_roles("Admin", "Operator")       # ack / close / sửa luật (Operator theo phạm vi)

State = Literal["open", "ack", "closed"]
RuleType = Literal["LOW_LEVEL", "HIGH_LEVEL", "LEAK_SUSPECT", "PUMP_NO_RISE", "DEVICE_OFFLINE"]


class AlertOut(BaseModel):
    id: int
    device_id: int
    device_code: str
    device_name: str
    type: str
    severity: str
    value: float
    state: State
    opened_at: datetime
    acked_by: str | None
    acked_at: datetime | None
    closed_at: datetime | None


class AlertPage(BaseModel):
    total: int
    items: list[AlertOut]


class RuleOut(BaseModel):
    type: str
    enabled: bool
    severity: str
    params: dict


class RuleUpdate(BaseModel):
    type: RuleType
    enabled: bool | None = None
    severity: Literal["warning", "critical"] | None = None
    params: dict[str, float] | None = None


class RulesUpdateIn(BaseModel):
    rules: list[RuleUpdate] = Field(min_length=1, max_length=5)


def _utc(dt: datetime | None) -> datetime | None:
    return None if dt is None else dt.replace(tzinfo=timezone.utc)


def _out(a: Alert, dev: Device, acked_by_email: str | None) -> AlertOut:
    return AlertOut(id=a.id, device_id=a.device_id, device_code=dev.device_code, device_name=dev.name,
                    type=a.type, severity=a.severity, value=a.value, state=a.state, opened_at=_utc(a.opened_at),
                    acked_by=acked_by_email, acked_at=_utc(a.acked_at), closed_at=_utc(a.closed_at))


@router.get("/alerts", response_model=AlertPage)
def list_alerts(state: State | None = None, device_id: int | None = None, type: RuleType | None = None,
                limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
                s: Session = Depends(get_db), actor: Actor = Depends(any_user)):
    """Danh sách cảnh báo (lọc theo trạng thái, thiết bị, loại; có phân trang)"""
    conds = []
    if actor.role != "Admin":       # theo phạm vi được gán
        conds.append(Alert.device_id.in_(select(UserDevice.device_id).where(UserDevice.user_id == actor.id)))
    if state:
        conds.append(Alert.state == state)
    if device_id is not None:
        conds.append(Alert.device_id == device_id)
    if type:
        conds.append(Alert.type == type)
    total = s.scalar(select(func.count()).select_from(Alert).where(*conds)) or 0
    rows = s.execute(select(Alert, Device, User.email).join(Device, Device.id == Alert.device_id)
                     .outerjoin(User, User.id == Alert.acked_by).where(*conds)
                     .order_by(Alert.opened_at.desc(), Alert.id.desc()).limit(limit).offset(offset)).all()
    return AlertPage(total=total, items=[_out(a, d, email) for a, d, email in rows])


def _load(s: Session, actor: Actor, alert_id: int) -> tuple[Alert, Device]:
    a = s.get(Alert, alert_id)
    if a is None:
        raise NotFound("Không tìm thấy cảnh báo")
    return a, get_device_in_scope(s, actor, a.device_id)      # ngoài phạm vi cũng là 404 (S1)


def _transition(s: Session, actor: Actor, alert_id: int, from_states: tuple, values: dict, action: str) -> AlertOut:
    a, dev = _load(s, actor, alert_id)
    res = s.execute(update(Alert).where(Alert.id == a.id, Alert.state.in_(from_states)).values(**values))
    if res.rowcount != 1:
        s.rollback()
        raise Conflict(f"Cảnh báo đang ở trạng thái {a.state}, không thể thực hiện thao tác này")
    write_audit(s, actor.id, action, "alert", a.id, actor.ip, f"device={dev.device_code} type={a.type}")
    s.commit()
    s.refresh(a)
    emit("alert", engine.alert_event(a, dev))
    email = s.scalar(select(User.email).where(User.id == a.acked_by)) if a.acked_by else None
    return _out(a, dev, email)


@router.post("/alerts/{alert_id}/ack", response_model=AlertOut)
def ack_alert(alert_id: int, s: Session = Depends(get_db), actor: Actor = Depends(handlers)):
    """Xác nhận đã nhận cảnh báo (open → ack)"""
    return _transition(s, actor, alert_id, ("open",),
                       {"state": "ack", "acked_by": actor.id, "acked_at": utcnow()}, "alert.ack")


@router.post("/alerts/{alert_id}/close", response_model=AlertOut)
def close_alert(alert_id: int, s: Session = Depends(get_db), actor: Actor = Depends(handlers)):
    """Đóng thủ công (từ open hoặc ack). Nếu điều kiện còn đúng, cảnh báo mới chỉ sinh lại sau cooldown."""
    return _transition(s, actor, alert_id, ("open", "ack"),
                       {"state": "closed", "closed_at": utcnow()}, "alert.close")


def _rules_out(rules: dict) -> list[RuleOut]:
    return [RuleOut(type=t, enabled=rules[t].enabled, severity=rules[t].severity, params=rules[t].params)
            for t in engine.ALERT_TYPES if t in rules]


@router.get("/devices/{device_id}/alert-rules", response_model=list[RuleOut])
def get_rules(device_id: int, s: Session = Depends(get_db), actor: Actor = Depends(any_user)):
    """Xem các quy tắc cảnh báo của thiết bị (tự tạo mặc định nếu chưa có)"""
    dev = get_device_in_scope(s, actor, device_id)
    rules = engine.load_rules(s, dev)
    s.commit()          # lưu luật mặc định vừa tạo (nếu thiết bị chưa có)
    return _rules_out(rules)


@router.put("/devices/{device_id}/alert-rules", response_model=list[RuleOut])
def put_rules(device_id: int, body: RulesUpdateIn, s: Session = Depends(get_db), actor: Actor = Depends(handlers)):
    """Sửa thời gian tối thiểu, hysteresis, cooldown, mức độ, bật/tắt của quy tắc cảnh báo"""
    dev = get_device_in_scope(s, actor, device_id)
    updates = [u.model_dump(exclude_none=True) for u in body.rules]
    return _rules_out(engine.apply_rule_updates(s, dev, updates, actor_id=actor.id, ip=actor.ip))
