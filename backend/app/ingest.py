"""Xử lý bản tin MQTT. Thứ tự telemetry (mục 6.4):
parse -> kiểm tra schema/dải -> kiểm tra thiết bị -> loại trùng -> lưu -> last_seen -> (quy tắc) -> đẩy WebSocket
"""
import json
import logging
import threading
import time
from collections import defaultdict, deque
from datetime import timedelta

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from . import alerts, commands
from .config import settings
from .db import session_scope, utcnow
from .events import emit as _emit
from .events import set_event_callback  # noqa: F401  (giữ API cũ)
from .models import Device, Telemetry
from .schemas import StatusIn, TelemetryIn, missing_fields

log = logging.getLogger("ingest")

# Chỉ ghi dữ liệu của thiết bị đang hoạt động (lớp bảo vệ thứ hai ở mục 5).
# Fault vẫn nhận để quan sát; Maintenance/Decommissioned/Registered/Provisioned bị loại.
INGEST_STATES = {"Active", "Offline", "Fault"}
STATUS_STATES = {"Provisioned", "Active", "Offline", "Fault"}

# ---- Giới hạn tần suất theo thiết bị (chống tràn bản tin) -------------------
_rate: dict[str, deque] = defaultdict(deque)
_rate_lock = threading.Lock()


def _rate_limited(device_code: str) -> bool:
    now = time.monotonic()
    with _rate_lock:
        dq = _rate[device_code]
        while dq and now - dq[0] > settings.rate_limit_window_s:
            dq.popleft()
        if len(dq) >= settings.rate_limit_msgs:
            return True
        dq.append(now)
        return False


# ---- Điểm vào chung ---------------------------------------------------------
def handle_message(topic: str, payload: bytes, retained: bool = False) -> None:
    parts = topic.split("/")
    if len(parts) != 3 or parts[0] != "wms":
        log.warning("unexpected topic: %s", topic[:100])
        return
    _, device_code, kind = parts

    if len(payload) > settings.max_payload_bytes:
        log.warning("payload too large device=%s size=%d", device_code, len(payload))
        return
    if _rate_limited(device_code):
        log.warning("rate limited device=%s", device_code)
        return
    try:
        data = json.loads(payload)
    except (ValueError, UnicodeDecodeError):
        log.warning("invalid JSON device=%s topic=%s", device_code, kind)
        return
    if not isinstance(data, dict):
        log.warning("payload is not an object device=%s", device_code)
        return

    if kind == "telemetry":
        _handle_telemetry(device_code, data)
    elif kind == "status":
        _handle_status(device_code, data, retained)
    elif kind == "ack":
        commands.handle_ack(device_code, data)
    else:
        log.debug("ignored topic kind=%s device=%s", kind, device_code)


# ---- Telemetry --------------------------------------------------------------
def _handle_telemetry(device_code: str, data: dict) -> None:
    try:
        msg = TelemetryIn.model_validate(data)
    except ValidationError as e:
        problems = [(".".join(map(str, x["loc"])), x["msg"]) for x in e.errors()][:5]
        log.warning("reject telemetry device=%s invalid=%s", device_code, problems)
        return

    # Chống giả mạo: device_id trong payload phải khớp topic (topic đã bị ACL ràng buộc theo username)
    if msg.device_id != device_code:
        log.warning("reject telemetry: device_id mismatch topic=%s payload=%s", device_code, msg.device_id[:64])
        return

    now = utcnow()
    if abs((now - msg.ts).total_seconds()) > settings.ts_tolerance_s:
        log.warning("reject telemetry device=%s: ts out of tolerance (%s)", device_code, msg.ts)
        return

    with session_scope() as s:
        dev = s.scalars(select(Device).where(Device.device_code == device_code)).first()
        if dev is None or dev.state not in INGEST_STATES:
            log.warning("reject telemetry device=%s: unknown or state=%s",
                        device_code, dev.state if dev else None)
            return

        # Trường bắt buộc phụ thuộc loại node: node bồn gửi distance_cm, level_pct; node ống gửi flow_lpm, flow_total_l, pump_on
        missing = missing_fields(msg, dev.type)
        if missing:
            log.warning("reject telemetry device=%s (node %s): thiếu %s", device_code, dev.type, missing)
            return
        is_tank = dev.type == "tank"
        row = Telemetry(
            device_id=dev.id, boot_id=msg.boot_id, seq=msg.seq, ts=msg.ts, received_at=now,
            # Trường không thuộc loại node này bị bỏ qua (không lưu), tránh làm sai dữ liệu của node kia
            distance_cm=msg.distance_cm if is_tank else None, level_pct=msg.level_pct if is_tank else None,
            flow_lpm=None if is_tank else msg.flow_lpm, flow_total_l=None if is_tank else msg.flow_total_l,
            pump_on=None if is_tank else msg.pump_on, rssi=msg.rssi,
        )
        try:
            with s.begin_nested():          # savepoint: trùng khóa chỉ hủy riêng dòng này
                s.add(row)
        except IntegrityError:
            log.info("duplicate telemetry device=%s boot=%s seq=%d", device_code, msg.boot_id, msg.seq)
            return

        was_offline = dev.state == "Offline" or not dev.online
        dev.last_seen = now
        dev.online = True
        if dev.state == "Offline":          # có dữ liệu lại -> Active
            dev.state = "Active"

        event = {
            "device_code": device_code, "device_id": dev.id, "type": dev.type, "site_id": dev.site_id,
            "state": dev.state, "ts": msg.ts.isoformat() + "Z", "received_at": now.isoformat() + "Z",
            "distance_cm": row.distance_cm, "level_pct": row.level_pct, "flow_lpm": row.flow_lpm,
            "flow_total_l": row.flow_total_l, "pump_on": row.pump_on,
        }
        sample = alerts.Sample(device_id=dev.id, ts=msg.ts, level_pct=row.level_pct,
                               flow_lpm=row.flow_lpm, pump_on=row.pump_on)

    # Sau khi commit: đóng DEVICE_OFFLINE nếu vừa có dữ liệu lại, rồi chạy quy tắc cảnh báo
    if was_offline:
        alerts.on_device_online(event["device_id"])
    alerts.evaluate(sample)
    _emit("telemetry", event)


# ---- Status / heartbeat / LWT -----------------------------------------------
def _handle_status(device_code: str, data: dict, retained: bool) -> None:
    try:
        msg = StatusIn.model_validate(data)
    except ValidationError as e:
        log.warning("reject status device=%s invalid=%s", device_code,
                    [(".".join(map(str, x["loc"])), x["msg"]) for x in e.errors()][:5])
        return

    # Bản retained "online" có thể là của thiết bị đã chết trước khi backend khởi động;
    # bỏ qua, heartbeat 30s sau sẽ cập nhật đúng.
    if retained and msg.status == "online":
        return

    now = utcnow()
    with session_scope() as s:
        dev = s.scalars(select(Device).where(Device.device_code == device_code)).first()
        if dev is None or dev.state not in STATUS_STATES:
            log.warning("reject status device=%s: unknown or state=%s",
                        device_code, dev.state if dev else None)
            return

        was_offline = dev.state == "Offline" or not dev.online
        applied_event = None
        if msg.status == "online":
            dev.online = True
            dev.last_seen = now
            if msg.fw_version:
                dev.fw_version = msg.fw_version
            if msg.config_version is not None and dev.config_applied_version != msg.config_version:
                dev.config_applied_version = msg.config_version
                applied_event = {"device_code": device_code, "device_id": dev.id,
                                 "applied_version": msg.config_version}
            if dev.state in ("Provisioned", "Offline"):   # kết nối lần đầu / có heartbeat lại
                dev.state = "Active"
            if msg.free_heap is not None:
                log.info("heartbeat device=%s free_heap=%d", device_code, msg.free_heap)
        else:                                              # LWT hoặc thiết bị tự báo offline
            dev.online = False
            if dev.state == "Active":
                dev.state = "Offline"

        event = {"device_code": device_code, "device_id": dev.id, "type": dev.type, "site_id": dev.site_id,
                 "state": dev.state, "online": dev.online, "fw_version": dev.fw_version}

    _emit("device_state", event)
    if applied_event:
        _emit("config_applied", applied_event)
    if msg.status == "online":
        if was_offline:
            alerts.on_device_online(event["device_id"])
    else:
        alerts.on_device_offline(event["device_id"])


# ---- Phát hiện mất heartbeat ------------------------------------------------
def mark_stale_offline() -> int:
    cutoff = utcnow() - timedelta(seconds=settings.heartbeat_timeout_s)
    events = []
    with session_scope() as s:
        stale = s.scalars(select(Device).where(Device.online.is_(True), Device.last_seen < cutoff)).all()
        for dev in stale:
            dev.online = False
            if dev.state == "Active":
                dev.state = "Offline"
            events.append({"device_code": dev.device_code, "device_id": dev.id, "type": dev.type,
                           "site_id": dev.site_id, "state": dev.state, "online": False,
                           "fw_version": dev.fw_version})
    for ev in events:
        log.warning("heartbeat timeout device=%s", ev["device_code"])
        _emit("device_state", ev)
        alerts.on_device_offline(ev["device_id"])
    return len(events)


def run_offline_watcher(stop: threading.Event, interval_s: float = 10.0) -> None:
    while not stop.wait(interval_s):
        try:
            mark_stale_offline()
        except Exception:
            log.exception("offline watcher error")
