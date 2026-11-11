"""Vòng đời thiết bị (mục 5): Registered -> Provisioned -> Active -> ... -> Decommissioned."""
import hashlib
import logging
import secrets

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .audit import write_audit
from .broker_admin import BrokerAdmin, BrokerError
from .db import utcnow
from .events import emit
from .models import DEVICE_TYPES, Device, DeviceCredential, Site

log = logging.getLogger("lifecycle")

# Theo sơ đồ trạng thái ở mục 2. Bổ sung 1 cạnh ngoài sơ đồ: Provisioned -> Decommissioned
# (để thu hồi credential đã cấp mà thiết bị chưa từng kết nối). Sửa sơ đồ nếu nhóm đồng ý.
TRANSITIONS: dict[str, set[str]] = {
    "Registered": {"Provisioned"},
    "Provisioned": {"Active", "Decommissioned"},
    "Active": {"Offline", "Fault", "Maintenance", "Decommissioned"},
    "Offline": {"Active", "Decommissioned"},
    "Fault": {"Maintenance"},
    "Maintenance": {"Active", "Decommissioned"},
    "Decommissioned": set(),
}
# Đích do con người đặt qua API. Offline/Fault do hệ thống tự chuyển (ingest, alert engine);
# Provisioned đi qua provision().
MANUAL_TARGETS = {"Active", "Maintenance", "Decommissioned"}


class LifecycleError(Exception):
    pass


class NotFound(LifecycleError):
    pass


class Conflict(LifecycleError):
    pass


class InvalidReference(LifecycleError):
    """Giá trị tham chiếu không hợp lệ (loại thiết bị lạ, site không tồn tại...): 422."""


class InvalidTransition(LifecycleError):
    def __init__(self, current: str, target: str):
        super().__init__(f"Không thể chuyển {current} -> {target}")
        self.current, self.target = current, target


def can_transition(current: str, target: str) -> bool:
    return target in TRANSITIONS.get(current, set())


def hash_secret(secret: str) -> str:
    # Secret ngẫu nhiên 192 bit nên SHA-256 là đủ (không cần bcrypt như mật khẩu người dùng)
    return hashlib.sha256(secret.encode()).hexdigest()


def _announce(dev: Device) -> None:
    """Báo thay đổi trạng thái vòng đời cho dashboard (WebSocket)."""
    emit("device_state", {"device_code": dev.device_code, "device_id": dev.id, "type": dev.type, "site_id": dev.site_id,
                          "state": dev.state, "online": dev.online, "fw_version": dev.fw_version})


def get_device(s: Session, device_id: int) -> Device:
    dev = s.get(Device, device_id)
    if dev is None:
        raise NotFound("Không tìm thấy thiết bị")   # sau này: cả trường hợp ngoài phạm vi
    return dev


SLOT_NAMES = {"tank": "node bồn (tank)", "pipe": "node ống (pipe)"}


def _check_site_slot(s: Session, site_id: int | None, device_type: str, exclude_id: int | None = None) -> None:
    """Mỗi site có tối đa một node bồn và một node ống (không tính thiết bị đã thu hồi)."""
    if site_id is None:
        return
    if s.get(Site, site_id) is None:
        raise InvalidReference(f"Site {site_id} không tồn tại")
    stmt = select(Device.id).where(Device.site_id == site_id, Device.type == device_type,
                                   Device.state != "Decommissioned")
    if exclude_id is not None:
        stmt = stmt.where(Device.id != exclude_id)
    if s.scalars(stmt).first() is not None:
        raise Conflict(f"Site đã có {SLOT_NAMES[device_type]}")


def create_device(s: Session, *, device_code: str, name: str, hw_version: str, device_type: str,
                  site_id: int | None = None, actor_id: int | None, ip: str) -> Device:
    if device_type not in DEVICE_TYPES:
        raise InvalidReference(f"Loại thiết bị phải thuộc {DEVICE_TYPES}")
    if s.scalars(select(Device).where(Device.device_code == device_code)).first():
        raise Conflict(f"Mã thiết bị '{device_code}' đã tồn tại")
    _check_site_slot(s, site_id, device_type)
    dev = Device(device_code=device_code, name=name, type=device_type, site_id=site_id,
                 hw_version=hw_version, state="Registered")
    s.add(dev)
    try:
        s.flush()
        write_audit(s, actor_id, "device.create", "device", dev.id, ip,
                    f"code={device_code} type={device_type} site={site_id}")
        s.commit()
    except IntegrityError:
        s.rollback()
        raise Conflict(f"Mã thiết bị '{device_code}' đã tồn tại")
    _announce(dev)
    return dev


def assign_site(s: Session, device_id: int, site_id: int | None, *, actor_id: int | None, ip: str) -> Device:
    """Đưa thiết bị vào site (hoặc ra khỏi site khi site_id=None). Hai node cùng site mới phối hợp được với nhau."""
    dev = get_device(s, device_id)
    if dev.state == "Decommissioned":
        raise Conflict("Thiết bị đã bị thu hồi")
    _check_site_slot(s, site_id, dev.type, exclude_id=dev.id)
    old = dev.site_id
    dev.site_id = site_id
    write_audit(s, actor_id, "device.site", "device", dev.id, ip, f"{old}->{site_id}")
    s.commit()
    _announce(dev)
    return dev


def create_site(s: Session, *, name: str, description: str, actor_id: int | None, ip: str) -> Site:
    name = name.strip()
    if not name:
        raise InvalidReference("Tên site không được để trống")
    if s.scalars(select(Site).where(Site.name == name)).first():
        raise Conflict(f"Site '{name}' đã tồn tại")
    site = Site(name=name, description=description)
    s.add(site)
    try:
        s.flush()
        write_audit(s, actor_id, "site.create", "site", site.id, ip, f"name={name}")
        s.commit()
    except IntegrityError:
        s.rollback()
        raise Conflict(f"Site '{name}' đã tồn tại")
    return site


def provision(s: Session, broker: BrokerAdmin, device_id: int, *,
              actor_id: int | None, ip: str) -> tuple[Device, str]:
    """Registered -> Provisioned. Trả (device, mật khẩu gốc); mật khẩu chỉ tồn tại ở giá trị trả về."""
    dev = get_device(s, device_id)
    if dev.state != "Registered":
        raise InvalidTransition(dev.state, "Provisioned")
    code = dev.device_code
    secret = secrets.token_urlsafe(24)

    broker.create_client(code, secret)          # lỗi broker -> BrokerError, DB chưa đổi gì
    try:
        s.add(DeviceCredential(device_id=dev.id, mqtt_username=code, secret_hash=hash_secret(secret)))
        dev.state = "Provisioned"
        write_audit(s, actor_id, "device.provision", "device", dev.id, ip, f"username={code}")
        s.commit()
    except Exception:
        s.rollback()
        try:
            broker.delete_client(code)           # bù trừ: không để tài khoản mồ côi trên broker
        except BrokerError:
            log.exception("không xóa được tài khoản mồ côi %s trên broker", code)
        raise
    _announce(dev)
    return dev, secret


def change_state(s: Session, broker: BrokerAdmin, device_id: int, target: str, *,
                 actor_id: int | None, ip: str) -> Device:
    dev = get_device(s, device_id)
    current, code = dev.state, dev.device_code
    if target not in MANUAL_TARGETS or not can_transition(current, target):
        raise InvalidTransition(current, target)

    # Gọi broker TRƯỚC khi commit: nếu broker lỗi thì trạng thái trong DB không đổi
    if target == "Maintenance":
        broker.set_enabled(code, False)          # ngắt kết nối, không nhận dữ liệu
        dev.online = False
    elif target == "Active" and current == "Maintenance":
        broker.set_enabled(code, True)
    elif target == "Decommissioned":
        broker.delete_client(code)               # thu hồi: xóa tài khoản broker, ngắt ngay
        dev.online = False
        cred = s.scalars(select(DeviceCredential).where(DeviceCredential.device_id == dev.id)).first()
        if cred and cred.revoked_at is None:
            cred.revoked_at = utcnow()

    dev.state = target
    write_audit(s, actor_id, "device.state", "device", dev.id, ip, f"{current}->{target}")
    try:
        s.commit()
    except Exception:
        s.rollback()
        log.exception("commit thất bại sau khi đã đổi broker (device=%s %s->%s): cần đối soát", code, current, target)
        raise
    _announce(dev)
    return dev
