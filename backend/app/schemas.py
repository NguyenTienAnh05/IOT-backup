from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class TelemetryIn(BaseModel):
    """Bản tin wms/{deviceId}/telemetry. Ngoài dải hoặc thiếu trường -> ValidationError (S5)."""
    model_config = ConfigDict(extra="ignore")

    device_id: str = Field(min_length=1, max_length=64)
    boot_id: str = Field(min_length=1, max_length=16)
    seq: int = Field(ge=0, le=2**53)    # cột BIGINT; chặn giá trị phi thực tế
    ts: datetime
    # Trường theo loại node (kiểm tra bắt buộc ở ingest sau khi biết loại thiết bị, xem REQUIRED_BY_TYPE)
    distance_cm: float | None = Field(default=None, ge=0, le=1000)      # node bồn
    level_pct: float | None = Field(default=None, ge=0, le=100)         # node bồn
    flow_lpm: float | None = Field(default=None, ge=0, le=100)          # node ống
    flow_total_l: float | None = Field(default=None, ge=0)              # node ống
    pump_on: bool | None = None                                         # node ống
    rssi: int | None = Field(default=None, ge=-120, le=0)

    @field_validator("ts")
    @classmethod
    def ts_to_naive_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("ts phải có múi giờ (ví dụ hậu tố Z)")
        return v.astimezone(timezone.utc).replace(tzinfo=None)


REQUIRED_BY_TYPE = {"tank": ("distance_cm", "level_pct"), "pipe": ("flow_lpm", "flow_total_l", "pump_on")}


def missing_fields(msg: TelemetryIn, device_type: str) -> list[str]:
    return [f for f in REQUIRED_BY_TYPE.get(device_type, ()) if getattr(msg, f) is None]


class StatusIn(BaseModel):
    """Bản tin wms/{deviceId}/status (online/heartbeat/LWT), payload là JSON."""
    model_config = ConfigDict(extra="ignore")

    status: Literal["online", "offline"]
    fw_version: str | None = Field(default=None, max_length=32)
    free_heap: int | None = Field(default=None, ge=0)
    config_version: int | None = Field(default=None, ge=0)     # phiên bản cấu hình thiết bị đang áp dụng


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    email: str
    full_name: str
    role: str
    status: str
    locked: bool
    created_at: datetime


class AckIn(BaseModel):
    """Bản tin wms/{deviceId}/ack. result: ok = bơm đã làm đúng lệnh; fail = thiết bị từ chối/không làm được
    (reason: expired, duplicate, over_limit, ...)."""
    model_config = ConfigDict(extra="ignore")

    cmd_id: str = Field(min_length=1, max_length=64)
    result: Literal["ok", "fail"]
    reason: str | None = Field(default=None, max_length=128)
    ts: datetime | None = None
