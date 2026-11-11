"""Cấu hình thiết bị: lưu có version, publish RETAINED xuống wms/{deviceId}/config (QoS 1).

Retained: thiết bị mới kết nối/kết nối lại sẽ nhận ngay cấu hình mới nhất. Thiết bị báo phiên bản đang áp dụng
trong heartbeat (status.config_version) nên backend phân biệt được 'đã áp dụng' và 'đang chờ'."""
import json
import logging
import threading
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import alerts, device_params
from .audit import write_audit
from .db import utcnow
from .errors import InvalidInput, PublishError
from .events import emit
from .lifecycle import Conflict
from .models import Device, DeviceConfig, User

log = logging.getLogger("device_config")
_lock = threading.Lock()       # tuần tự hóa sửa+publish cấu hình (1 tiến trình): retained luôn là bản mới nhất


def sync_status(version: int, applied: int | None) -> str:
    if version == 0:
        return "default"            # chưa lưu cấu hình nào, thiết bị dùng mặc định
    if applied is None:
        return "unknown"            # thiết bị chưa báo phiên bản đang áp dụng
    if applied == version:
        return "applied"
    return "pending" if applied < version else "mismatch"


def _iso(dt: datetime | None) -> str | None:
    return None if dt is None else dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def get_state(s: Session, dev: Device) -> dict:
    cfg = device_params.get_config(s, dev.id)
    version = device_params.get_version(s, dev.id)
    last = None
    if version:
        last = s.execute(select(DeviceConfig.updated_at, User.email)
                         .outerjoin(User, User.id == DeviceConfig.updated_by)
                         .where(DeviceConfig.device_id == dev.id, DeviceConfig.version == version)
                         .order_by(DeviceConfig.updated_at.desc()).limit(1)).first()
    return {"device_id": dev.id, "version": version, "config": device_params.to_public(cfg),
            "limits": device_params.limits(), "applied_version": dev.config_applied_version,
            "sync_status": sync_status(version, dev.config_applied_version),
            "updated_at": last[0] if last else None, "updated_by": last[1] if last else None}


def _event(dev: Device, state: dict) -> dict:
    return {"device_code": dev.device_code, "device_id": dev.id, "version": state["version"],
            "config": state["config"], "sync_status": state["sync_status"], "updated_at": _iso(state["updated_at"])}


def _publish(publisher, dev: Device, wire: dict) -> str:
    try:
        publisher.publish(f"wms/{dev.device_code}/config", json.dumps(wire), qos=1, retain=True)
        return "published"
    except PublishError as e:
        log.warning("không publish được config device=%s: %s", dev.device_code, e)
        return "failed"


def update_config(s: Session, publisher, dev: Device, updates: dict, *, expected_version: int | None,
                  actor_id: int, ip: str) -> tuple[dict, list[str], str]:
    """Trả (trạng thái cấu hình, danh sách khóa đã đổi, delivery: published | failed | unchanged)."""
    if not updates:
        raise InvalidInput("Không có trường cấu hình nào để cập nhật")
    with _lock:
        if dev.state == "Decommissioned":
            raise Conflict("Thiết bị đã bị thu hồi, không thể đổi cấu hình")
        version = device_params.get_version(s, dev.id)
        if expected_version is not None and expected_version != version:
            raise Conflict(f"Cấu hình đã thay đổi (hiện là phiên bản {version}), hãy tải lại trước khi sửa")
        current = device_params.get_config(s, dev.id)
        changes = device_params.validate_update(updates, current)
        if not changes:
            return get_state(s, dev), [], "unchanged"

        new_version, now = version + 1, utcnow()
        rows = {r.key: r for r in s.scalars(select(DeviceConfig).where(DeviceConfig.device_id == dev.id))}
        for key, value in changes.items():
            row = rows.get(key)
            if row is None:
                s.add(DeviceConfig(device_id=dev.id, key=key, value=device_params.store(value),
                                   version=new_version, updated_by=actor_id, updated_at=now))
            else:
                row.value, row.version = device_params.store(value), new_version
                row.updated_by, row.updated_at = actor_id, now
        diff = "; ".join(f"{k} {current[k]}->{v}" for k, v in changes.items())
        write_audit(s, actor_id, "config.update", "device", dev.id, ip, f"v{version}->v{new_version}: {diff}")
        s.commit()
        alerts.invalidate(dev.id)       # alert engine đọc ngưỡng mới ngay, không đợi hết cache

        state = get_state(s, dev)
        delivery = _publish(publisher, dev, device_params.to_wire(device_params.get_config(s, dev.id), new_version))
    emit("config", _event(dev, state))
    return state, sorted(changes), delivery


def publish_current(s: Session, publisher, dev: Device, *, actor_id: int, ip: str) -> tuple[dict, str]:
    """Gửi lại cấu hình hiện tại (retained). Dùng khi lần gửi trước thất bại hoặc broker mất retained."""
    with _lock:
        if dev.state == "Decommissioned":
            raise Conflict("Thiết bị đã bị thu hồi")
        version = device_params.get_version(s, dev.id)
        if version == 0:
            raise Conflict("Chưa có cấu hình nào được lưu, hãy lưu cấu hình trước")
        delivery = _publish(publisher, dev, device_params.to_wire(device_params.get_config(s, dev.id), version))
        write_audit(s, actor_id, "config.publish", "device", dev.id, ip, f"v{version} {delivery}")
        s.commit()
        return get_state(s, dev), delivery
