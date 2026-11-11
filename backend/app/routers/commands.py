import json
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import commands
from ..access import get_device_in_scope
from ..deps import Actor, get_db, require_roles
from ..lifecycle import NotFound
from ..models import Command, User
from ..mqtt_client import get_subscriber

router = APIRouter(prefix="/api/devices/{device_id}/commands", tags=["commands"])
operators = require_roles("Admin", "Operator")      # Viewer không gửi và không xem lệnh


def get_publisher() -> commands.Publisher:
    return get_subscriber()


class CommandIn(BaseModel):
    action: Literal["pump"] = "pump"
    value: Literal["on", "off"]
    duration_s: int | None = Field(default=None, ge=1, le=3600)     # chỉ dùng khi on; mặc định 60, tối đa theo cấu hình


class CommandOut(BaseModel):
    cmd_id: str
    device_id: int
    user_id: int | None
    user_email: str | None
    action: str
    value: str
    duration_s: int | None
    status: Literal["sent", "ok", "fail", "timeout"]
    sent_at: datetime
    acked_at: datetime | None
    reason: str
    source: str | None = None       # None = người dùng gửi; "auto:..." = alert engine


def _utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc)


def _out(c: Command, email: str | None) -> CommandOut:
    params = json.loads(c.params_json or "{}")
    return CommandOut(cmd_id=c.cmd_id, device_id=c.device_id, user_id=c.user_id, user_email=email,
                      action=c.action, value=params.get("value", ""), duration_s=params.get("duration_s"),
                      status=c.status, sent_at=_utc(c.sent_at),
                      acked_at=_utc(c.acked_at) if c.acked_at else None, reason=c.reason,
                      source=params.get("source"))


@router.post("", response_model=CommandOut, status_code=202)
def send_command(device_id: int, body: CommandIn, s: Session = Depends(get_db),
                 publisher: commands.Publisher = Depends(get_publisher), actor: Actor = Depends(operators)):
    """202: lệnh đã được ghi và gửi; kết quả (ok/fail/timeout) lấy qua GET .../{cmd_id} hoặc WebSocket."""
    dev = get_device_in_scope(s, actor, device_id)
    cmd = commands.send_pump_command(s, publisher, dev, value=body.value, duration_s=body.duration_s,
                                     actor_id=actor.id, ip=actor.ip)
    return _out(cmd, s.scalar(select(User.email).where(User.id == actor.id)))


@router.get("", response_model=list[CommandOut])
def list_commands(device_id: int, status: Literal["sent", "ok", "fail", "timeout"] | None = None,
                  limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
                  s: Session = Depends(get_db), actor: Actor = Depends(operators)):
    """Lịch sử lệnh bơm của thiết bị (kèm người gửi và trạng thái)"""
    dev = get_device_in_scope(s, actor, device_id)
    stmt = (select(Command, User.email).outerjoin(User, User.id == Command.user_id)
            .where(Command.device_id == dev.id).order_by(Command.id.desc()).limit(limit).offset(offset))
    if status:
        stmt = stmt.where(Command.status == status)
    return [_out(c, email) for c, email in s.execute(stmt).all()]


@router.get("/{cmd_id}", response_model=CommandOut)
def get_command(device_id: int, cmd_id: str, s: Session = Depends(get_db), actor: Actor = Depends(operators)):
    """Chi tiết một lệnh theo cmd_id (dùng để theo dõi kết quả)"""
    dev = get_device_in_scope(s, actor, device_id)
    row = s.execute(select(Command, User.email).outerjoin(User, User.id == Command.user_id)
                    .where(Command.device_id == dev.id, Command.cmd_id == cmd_id)).first()
    if row is None:
        raise NotFound("Không tìm thấy lệnh")
    return _out(*row)
