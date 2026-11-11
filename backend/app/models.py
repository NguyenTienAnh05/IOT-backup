from datetime import datetime

from sqlalchemy import (BigInteger, Boolean, DateTime, Float, ForeignKey, Index,
                        Integer, PrimaryKeyConstraint, String, Text, UniqueConstraint)
from sqlalchemy.dialects import mysql
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base, utcnow

# DATETIME(3): giữ mili-giây để đo độ trễ (ts thiết bị vs received_at)
DT_MS = DateTime().with_variant(mysql.DATETIME(fsp=3), "mysql")
# BIGINT autoincrement trên MySQL; sqlite (dùng khi chạy test) chỉ autoincrement với INTEGER
BIGINT_PK = BigInteger().with_variant(Integer, "sqlite")

# Hệ thống 2 node: node bồn (tank) đo mực nước + còi; node ống (pipe) đo lưu lượng + điều khiển bơm
DEVICE_TYPES = ("tank", "pipe")


class Device(Base):
    """Thiết bị. Schema chuẩn nằm ở database/migrations; model này phải khớp (có test)."""
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(primary_key=True)
    device_code: Mapped[str] = mapped_column(String(64), unique=True)
    name: Mapped[str] = mapped_column(String(128), default="")
    type: Mapped[str] = mapped_column(String(8))                      # "tank" hoặc "pipe"
    site_id: Mapped[int | None] = mapped_column(ForeignKey("sites.id"), nullable=True)
    state: Mapped[str] = mapped_column(String(20), default="Registered")
    hw_version: Mapped[str] = mapped_column(String(32), default="")
    fw_version: Mapped[str] = mapped_column(String(32), default="")
    config_applied_version: Mapped[int | None] = mapped_column(Integer, nullable=True)   # do thiết bị báo trong heartbeat
    online: Mapped[bool] = mapped_column(Boolean, default=False)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Telemetry(Base):
    __tablename__ = "telemetry"
    __table_args__ = (
        UniqueConstraint("device_id", "boot_id", "seq", name="uq_telemetry_dedupe"),
        Index("ix_telemetry_device_ts", "device_id", "ts"),
    )

    id: Mapped[int] = mapped_column(BIGINT_PK, primary_key=True, autoincrement=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"))
    boot_id: Mapped[str] = mapped_column(String(16))
    seq: Mapped[int] = mapped_column(BigInteger)
    ts: Mapped[datetime] = mapped_column(DT_MS)             # giờ thiết bị (NTP)
    received_at: Mapped[datetime] = mapped_column(DT_MS)    # giờ backend nhận
    # Cột không áp dụng cho loại node thì để NULL: node bồn có distance_cm, level_pct; node ống có flow_lpm, flow_total_l, pump_on
    distance_cm: Mapped[float | None] = mapped_column(Float, nullable=True)
    level_pct: Mapped[float | None] = mapped_column(Float, nullable=True)
    flow_lpm: Mapped[float | None] = mapped_column(Float, nullable=True)
    flow_total_l: Mapped[float | None] = mapped_column(Float, nullable=True)
    pump_on: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    rssi: Mapped[int | None] = mapped_column(Integer, nullable=True)


class DeviceCredential(Base):
    """Mỗi thiết bị 1 credential MQTT. Chỉ lưu bản băm; mật khẩu gốc chỉ hiện 1 lần khi cấp."""
    __tablename__ = "device_credentials"

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), unique=True)
    mqtt_username: Mapped[str] = mapped_column(String(64), unique=True)
    secret_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(BIGINT_PK, primary_key=True, autoincrement=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(64))
    target_type: Mapped[str] = mapped_column(String(32))
    target_id: Mapped[str] = mapped_column(String(64))
    ip: Mapped[str] = mapped_column(String(45), default="")
    detail: Mapped[str] = mapped_column(String(512), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True)
    password_hash: Mapped[str] = mapped_column(String(100))
    full_name: Mapped[str] = mapped_column(String(128), default="")
    role: Mapped[str] = mapped_column(String(16))                 # Admin | Operator | Viewer
    status: Mapped[str] = mapped_column(String(16), default="active")   # active | disabled
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    token_version: Mapped[int] = mapped_column(Integer, default=0)      # tăng lên = hủy mọi JWT đã cấp
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    @property
    def locked(self) -> bool:
        return bool(self.locked_until and self.locked_until > utcnow())


class UserDevice(Base):
    """Phạm vi truy cập của Operator/Viewer (Admin thấy tất cả)."""
    __tablename__ = "user_devices"
    __table_args__ = (PrimaryKeyConstraint("user_id", "device_id"),)

    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"))


class Command(Base):
    __tablename__ = "commands"
    __table_args__ = (Index("ix_commands_device_sent", "device_id", "sent_at"),)

    id: Mapped[int] = mapped_column(BIGINT_PK, primary_key=True, autoincrement=True)
    cmd_id: Mapped[str] = mapped_column(String(64), unique=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"))
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(32))
    params_json: Mapped[str] = mapped_column(Text, default="{}")
    status: Mapped[str] = mapped_column(String(16))          # sent | ok | fail | timeout
    sent_at: Mapped[datetime] = mapped_column(DT_MS)         # lúc API nhận yêu cầu (mốc đo độ trễ lệnh)
    acked_at: Mapped[datetime | None] = mapped_column(DT_MS, nullable=True)   # lúc backend nhận ack
    reason: Mapped[str] = mapped_column(String(255), default="")


class DeviceConfig(Base):
    """Cấu hình thiết bị dạng key/value (low_pct, high_pct, auto_mode, ...). Module config sẽ ghi bảng này
    và đẩy xuống topic config; alert engine chỉ đọc."""
    __tablename__ = "device_configs"
    __table_args__ = (UniqueConstraint("device_id", "key", name="uq_device_config_key"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"))
    key: Mapped[str] = mapped_column(String(64))
    value: Mapped[str] = mapped_column(String(255))
    version: Mapped[int] = mapped_column(Integer, default=1)
    updated_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class AlertRule(Base):
    __tablename__ = "alert_rules"
    __table_args__ = (UniqueConstraint("device_id", "type", name="uq_alert_rule_type"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"))
    type: Mapped[str] = mapped_column(String(32))
    params_json: Mapped[str] = mapped_column(Text, default="{}")
    severity: Mapped[str] = mapped_column(String(16), default="warning")    # warning | critical
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (Index("ix_alerts_device_state", "device_id", "state"),
                      Index("ix_alerts_opened", "opened_at"))

    id: Mapped[int] = mapped_column(BIGINT_PK, primary_key=True, autoincrement=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"))
    rule_id: Mapped[int | None] = mapped_column(ForeignKey("alert_rules.id"), nullable=True)
    type: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16))
    value: Mapped[float] = mapped_column(Float)          # số đo gây cảnh báo (mực %, cm/phút, giây mất heartbeat...)
    state: Mapped[str] = mapped_column(String(8))        # open | ack | closed
    opened_at: Mapped[datetime] = mapped_column(DT_MS)
    acked_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    acked_at: Mapped[datetime | None] = mapped_column(DT_MS, nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(DT_MS, nullable=True)


class Site(Base):
    """Khu vực/địa điểm đặt thiết bị (chưa có API quản lý)."""
    __tablename__ = "sites"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    description: Mapped[str] = mapped_column(String(255), default="")
