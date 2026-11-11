"""Dữ liệu mẫu cho dev (chạy được trên SQLite lẫn MySQL): 1 site có 2 node và 24 giờ telemetry giả (288 mẫu,
cách nhau 5 phút) để thử biểu đồ:
  wms-tank-01  node bồn (tank): mực nước, còi
  wms-pipe-01  node ống (pipe): lưu lượng, điều khiển bơm
Cả hai ở trạng thái Active, cùng site "Nhà mẫu" nên cảnh báo và tự động bật/tắt bơm phối hợp được giữa hai node.

Chạy từ thư mục backend/:   python -m scripts.seed_dev
Idempotent: chạy lại không nhân đôi dữ liệu. KHÔNG tạo tài khoản người dùng (xem scripts/create_user.py).
"""
import math
from datetime import timedelta

from sqlalchemy import select

from app import device_params
from app.db import Base, SessionLocal, engine, utcnow
from app.models import Device, DeviceConfig, Site, Telemetry

SAMPLES, STEP_MINUTES = 288, 5
NODES = (("wms-tank-01", "Node bồn (mực nước, còi)", "tank"),
         ("wms-pipe-01", "Node ống (lưu lượng, bơm)", "pipe"))


def _pumping(i: int) -> bool:
    return 40 <= i % 60 <= 47                      # bơm chạy 8 mẫu mỗi giờ


def _sample(dev_type: str, i: int) -> dict:
    if dev_type == "tank":
        level = round(55 + 30 * math.sin(i / 30), 1)                       # dao động 25-85%
        return {"distance_cm": round(25 * (1 - level / 100), 1), "level_pct": level, "rssi": -60}
    pumping = _pumping(i)
    return {"flow_lpm": 3.2 if pumping else 0.0, "flow_total_l": round(i * 0.8, 1), "pump_on": pumping, "rssi": -58}


def main() -> None:
    Base.metadata.create_all(engine)
    added = 0
    with SessionLocal() as s:
        site = s.scalars(select(Site).where(Site.name == "Nhà mẫu")).first()
        if site is None:
            site = Site(name="Nhà mẫu", description="Địa điểm demo: một node bồn và một node ống")
            s.add(site)
            s.flush()

        now = utcnow()
        for code, name, dev_type in NODES:
            dev = s.scalars(select(Device).where(Device.device_code == code)).first()
            if dev is None:
                dev = Device(device_code=code, name=name, type=dev_type, site_id=site.id, state="Active",
                             hw_version="v1", fw_version="0.1.0")
                s.add(dev)
                s.flush()

            have = {c.key for c in s.scalars(select(DeviceConfig).where(DeviceConfig.device_id == dev.id))}
            for key, value in device_params.DEFAULTS.items():
                if key not in have:
                    s.add(DeviceConfig(device_id=dev.id, key=key, value=device_params.store(value), version=1))

            if s.scalar(select(Telemetry.id).where(Telemetry.device_id == dev.id, Telemetry.boot_id == "seed").limit(1)) is None:
                for i in range(SAMPLES):
                    ts = now - timedelta(minutes=STEP_MINUTES * (SAMPLES - 1 - i))
                    s.add(Telemetry(device_id=dev.id, boot_id="seed", seq=i, ts=ts, received_at=ts, **_sample(dev_type, i)))
                    added += 1
        s.commit()
    print(f"Xong: site 'Nhà mẫu' với wms-tank-01 (tank) và wms-pipe-01 (pipe), cấu hình mặc định, +{added} mẫu telemetry")


if __name__ == "__main__":
    main()
