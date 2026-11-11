import json
import math

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import settings
from .errors import InvalidInput
from .models import DeviceConfig

DEFAULTS: dict[str, object] = {
    "sample_interval_s": 5,
    "tank_height_cm": 25.0,
    "low_pct": 20.0,
    "high_pct": 90.0,
    "pump_max_run_s": 120,
    "auto_mode": True,
    "leak_flow_lpm": 0.3,       # node ống: lưu lượng từ mức này trở lên khi bơm tắt bị coi là rò rỉ
    "leak_minutes": 10,         # ...nếu kéo dài liên tục quá số phút này
}
MIN_BAND_PCT = 10       # high_pct - low_pct tối thiểu (hysteresis 5 mỗi phía của cảnh báo mức nước)


def limits() -> dict[str, dict]:
    """Giới hạn từng khóa; pump_max_run_s bị chặn bởi trần cứng PUMP_MAX_DURATION_S (không sửa được qua API)."""
    return {
        "sample_interval_s": {"type": "int", "min": 1, "max": 300},
        "tank_height_cm": {"type": "float", "min": 5, "max": 500},
        "low_pct": {"type": "float", "min": 0, "max": 100},
        "high_pct": {"type": "float", "min": 0, "max": 100},
        "pump_max_run_s": {"type": "int", "min": 5, "max": settings.pump_max_duration_s},
        "auto_mode": {"type": "bool", "min": None, "max": None},
        "leak_flow_lpm": {"type": "float", "min": 0.05, "max": 10},
        "leak_minutes": {"type": "int", "min": 1, "max": 120},
    }


def _parse(key: str, raw: str):
    default = DEFAULTS[key]
    try:
        if isinstance(default, bool):           # bool phải kiểm trước int
            return str(raw).strip().lower() in ("true", "1", "yes")
        if isinstance(default, int):
            return int(float(raw))
        return float(raw)
    except (TypeError, ValueError):
        return default


def store(value) -> str:
    return json.dumps(value)            # True -> "true", 5 -> "5", 25.0 -> "25.0"


def get_config(s: Session, device_id: int) -> dict:
    cfg = dict(DEFAULTS)
    for row in s.scalars(select(DeviceConfig).where(DeviceConfig.device_id == device_id)):
        if row.key in DEFAULTS:
            cfg[row.key] = _parse(row.key, row.value)
    return cfg


def get_version(s: Session, device_id: int) -> int:
    return s.scalar(select(func.max(DeviceConfig.version)).where(DeviceConfig.device_id == device_id)) or 0


def to_public(cfg: dict) -> dict:
    """Số thực nguyên in như số nguyên (25.0 -> 25) cho khớp mẫu bản tin ở mục 4.2."""
    return {k: (int(v) if isinstance(v, float) and v.is_integer() else v) for k, v in
            ((k, cfg[k]) for k in DEFAULTS)}


def to_wire(cfg: dict, version: int) -> dict:
    return {"version": version, **to_public(cfg)}


def _coerce(key: str, raw, lim: dict):
    if lim["type"] == "bool":
        if not isinstance(raw, bool):
            raise InvalidInput(f"{key} phải là true hoặc false")
        return raw
    if isinstance(raw, bool) or not isinstance(raw, (int, float)) or not math.isfinite(raw):
        raise InvalidInput(f"{key} phải là một số")
    if lim["type"] == "int":
        if isinstance(raw, float) and not raw.is_integer():
            raise InvalidInput(f"{key} phải là số nguyên")
        value = int(raw)
    else:
        value = float(raw)
    if not (lim["min"] <= value <= lim["max"]):
        raise InvalidInput(f"{key} phải trong khoảng {lim['min']}..{lim['max']}")
    return value


def validate_update(updates: dict, current: dict) -> dict:
    """Kiểm tra kiểu, khoảng và ràng buộc chéo trên cấu hình sau khi gộp. Trả về chỉ các khóa THỰC SỰ đổi."""
    lim = limits()
    merged, changes = dict(current), {}
    for key, raw in updates.items():
        if key not in DEFAULTS:
            raise InvalidInput(f"Khóa cấu hình không hợp lệ: {key}")
        value = _coerce(key, raw, lim[key])
        merged[key] = value
        if value != current[key]:
            changes[key] = value
    if merged["high_pct"] - merged["low_pct"] < MIN_BAND_PCT:
        raise InvalidInput(f"high_pct phải lớn hơn low_pct ít nhất {MIN_BAND_PCT} điểm phần trăm")
    return changes
