"""Lệnh bơm: gửi (API) -> publish cmd -> nhận ack -> cập nhật; quá hạn không có ack thì timeout.

Trạng thái: sent -> ok | fail (từ ack) | timeout (không có ack sau COMMAND_TIMEOUT_S).
Ack đến muộn sau timeout vẫn được ghi nhận (thiết bị có thể đã chạy lệnh trong TTL 10s)."""
import json
import logging
import threading
import uuid
from datetime import timedelta
from typing import Protocol

from pydantic import ValidationError
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from .audit import write_audit
from .config import settings
from .db import session_scope, utcnow
from .device_params import get_config
from .errors import InvalidInput, PublishError
from .events import emit
from .lifecycle import Conflict
from .models import Command, Device
from .schemas import AckIn

log = logging.getLogger("commands")

ACK_STATES = {"Active", "Offline", "Fault"}     # trạng thái vẫn nhận ack (Offline: ack muộn sau khi nối lại)


class Publisher(Protocol):
    def publish(self, topic: str, payload: str, qos: int = 1, retain: bool = False) -> None: ...


def _iso(dt) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def send_pump_command(s: Session, publisher: Publisher, dev: Device, *, value: str,
                      duration_s: int | None, actor_id: int | None, ip: str,
                      source: str | None = None) -> Command:
    # 1. Kiểm tra điều kiện (RBAC và phạm vi đã kiểm ở router). actor_id=None: lệnh do hệ thống
    #    (alert engine) tự gửi, source cho biết lý do, ví dụ "auto:LOW_LEVEL".
    # Lệnh TẮT là lệnh an toàn nên vẫn được gửi khi thiết bị Fault (cần ngắt bơm sau PUMP_NO_RISE).
    if dev.type != "pipe":
        raise Conflict(f"Chỉ node ống (pipe) điều khiển bơm; thiết bị này là node {dev.type}")
    allowed = {"Active"} if value == "on" else {"Active", "Fault"}
    if dev.state not in allowed:
        raise Conflict(f"Thiết bị đang ở trạng thái {dev.state}, không nhận lệnh bơm")
    if not dev.online:
        raise Conflict("Thiết bị đang offline, không nhận lệnh bơm")
    if value == "on":
        # Giới hạn = min(trần cứng của hệ thống, pump_max_run_s trong cấu hình thiết bị): thiết bị tự ngắt ở mức đó
        max_s = min(settings.pump_max_duration_s, int(get_config(s, dev.id)["pump_max_run_s"]))
        duration_s = duration_s or min(settings.pump_default_duration_s, max_s)
        if duration_s > max_s:
            raise InvalidInput(f"Thời gian bơm tối đa {max_s} giây (giới hạn cấu hình của thiết bị)")
    else:
        duration_s = None
    # Lệnh bật không chồng lên lệnh đang chờ; lệnh tắt luôn được gửi
    if value == "on" and s.scalars(select(Command.id).where(Command.device_id == dev.id,
                                                            Command.status == "sent")).first():
        raise Conflict("Đang chờ phản hồi của lệnh trước, thử lại sau vài giây")

    # 2. Ghi lệnh (status=sent) và COMMIT trước khi publish: ack có thể về chỉ sau vài ms
    now = utcnow()
    cmd_id = str(uuid.uuid4())
    params = {"value": value, **({"duration_s": duration_s} if duration_s else {}),
              **({"source": source} if source else {})}
    cmd = Command(cmd_id=cmd_id, device_id=dev.id, user_id=actor_id, action="pump",
                  params_json=json.dumps(params), status="sent", sent_at=now, reason="")
    s.add(cmd)
    write_audit(s, actor_id, "command.send", "device", dev.id, ip, f"cmd={cmd_id} pump {json.dumps(params)}")
    s.commit()

    # 3. Publish QoS 1 xuống wms/{deviceId}/cmd
    payload = {"cmd_id": cmd_id, "action": "pump", "value": value,
               **({"duration_s": duration_s} if duration_s else {}),
               "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ")}
    try:
        publisher.publish(f"wms/{dev.device_code}/cmd", json.dumps(payload), qos=1)
    except PublishError as e:
        s.execute(update(Command).where(Command.id == cmd.id, Command.status == "sent")
                  .values(status="fail", reason=str(e)[:200]))
        write_audit(s, actor_id, "command.publish_failed", "device", dev.id, ip, f"cmd={cmd_id}")
        s.commit()
        raise
    return cmd


def _result_event(dev: Device, cmd_id: str, status: str, reason: str, acked_at) -> dict:
    return {"device_code": dev.device_code, "device_id": dev.id, "cmd_id": cmd_id,
            "status": status, "reason": reason, "acked_at": _iso(acked_at)}


def handle_ack(device_code: str, data: dict) -> None:
    try:
        msg = AckIn.model_validate(data)
    except ValidationError as e:
        log.warning("reject ack device=%s invalid=%s", device_code,
                    [(".".join(map(str, x["loc"])), x["msg"]) for x in e.errors()][:5])
        return

    now = utcnow()
    with session_scope() as s:
        dev = s.scalars(select(Device).where(Device.device_code == device_code)).first()
        if dev is None or dev.state not in ACK_STATES:
            log.warning("reject ack device=%s: unknown or state=%s", device_code, dev.state if dev else None)
            return
        cmd = s.scalars(select(Command).where(Command.cmd_id == msg.cmd_id)).first()
        # Ack chỉ có giá trị nếu đến từ đúng thiết bị được gửi lệnh
        if cmd is None or cmd.device_id != dev.id:
            log.warning("reject ack device=%s: cmd_id không thuộc thiết bị này", device_code)
            return

        reason = msg.reason or ""
        if cmd.status == "timeout":
            reason = (reason + " (ack muộn)").strip()
        # UPDATE có điều kiện để không ghi đè kết quả cuối cùng, kể cả khi trùng/đua với watcher timeout
        res = s.execute(update(Command).where(Command.id == cmd.id, Command.status.in_(("sent", "timeout")))
                        .values(status=msg.result, acked_at=now, reason=reason))
        if res.rowcount != 1:
            log.info("duplicate ack device=%s cmd=%s", device_code, msg.cmd_id)
            return
        write_audit(s, None, "command.ack", "command", msg.cmd_id, "",
                    f"device={device_code} result={msg.result} reason={reason}")
        event = _result_event(dev, msg.cmd_id, msg.result, reason, now)
    emit("command_result", event)


def mark_timed_out() -> int:
    cutoff = utcnow() - timedelta(seconds=settings.command_timeout_s)
    events = []
    with session_scope() as s:
        rows = s.execute(select(Command.id, Command.cmd_id, Command.device_id)
                         .where(Command.status == "sent", Command.sent_at < cutoff)).all()
        for row_id, cmd_id, device_id in rows:
            res = s.execute(update(Command).where(Command.id == row_id, Command.status == "sent")
                            .values(status="timeout", reason="Không nhận được ack"))
            if res.rowcount == 1:
                write_audit(s, None, "command.timeout", "command", cmd_id, "", f"device_id={device_id}")
                dev = s.get(Device, device_id)
                events.append(_result_event(dev, cmd_id, "timeout", "Không nhận được ack", utcnow()))
    for ev in events:
        log.warning("command timeout device=%s cmd=%s", ev["device_code"], ev["cmd_id"])
        emit("command_result", ev)
    return len(events)


def run_command_watcher(stop: threading.Event, interval_s: float = 1.0) -> None:
    while not stop.wait(interval_s):
        try:
            mark_timed_out()
        except Exception:
            log.exception("command watcher error")
