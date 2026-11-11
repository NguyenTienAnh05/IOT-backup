import csv
import io
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import Integer, cast, func, literal_column, select
from sqlalchemy.orm import Session

from ..access import get_device_in_scope
from ..audit import write_audit
from ..db import SessionLocal, engine, utcnow
from ..deps import Actor, any_user, get_db, require_roles
from ..errors import InvalidInput
from ..models import Telemetry

router = APIRouter(prefix="/api/devices/{device_id}/telemetry", tags=["telemetry"])

Interval = Literal["auto", "raw", "1m", "5m", "15m", "1h"]
BUCKET_SECONDS = {"1m": 60, "5m": 300, "15m": 900, "1h": 3600}
MAX_RANGE = timedelta(days=90)          # = thời gian lưu telemetry
MAX_RAW_RANGE = timedelta(hours=6)      # 6h x 12 mẫu/phút = 4320 < RAW_LIMIT
MAX_EXPORT_RANGE = timedelta(days=31)
RAW_LIMIT = 5000


class TelemetryPoint(BaseModel):
    """Trường không áp dụng cho loại node thì là null: node bồn có level_pct; node ống có flow_lpm, flow_total_l, pump_on."""
    ts: datetime
    level_pct: float | None = None
    flow_lpm: float | None = None
    flow_total_l: float | None = None
    pump_on: bool | None = None
    n: int = 1                  # số mẫu gốc trong điểm này (khi gộp)


class TelemetrySeries(BaseModel):
    device_id: int
    device_type: str
    interval: str
    start: datetime
    end: datetime
    points: list[TelemetryPoint]


class LatestOut(BaseModel):
    ts: datetime
    received_at: datetime
    device_type: str
    distance_cm: float | None = None    # node bồn
    level_pct: float | None = None      # node bồn
    flow_lpm: float | None = None       # node ống
    flow_total_l: float | None = None   # node ống
    pump_on: bool | None = None         # node ống
    rssi: int | None = None


def _utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc)


def _f(value) -> float | None:
    return None if value is None else float(value)


def _b(value) -> bool | None:
    return None if value is None else bool(value)


def _naive_utc(dt: datetime) -> datetime:
    return dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo else dt


def _resolve_range(from_: datetime | None, to: datetime | None, max_range: timedelta):
    end = _naive_utc(to) if to else utcnow()
    start = _naive_utc(from_) if from_ else end - timedelta(hours=1)
    if start >= end:
        raise InvalidInput("'from' phải nhỏ hơn 'to'")
    if end - start > max_range:
        raise InvalidInput(f"Khoảng thời gian tối đa {max_range.days} ngày")
    return start, end


def _auto_interval(span: timedelta) -> str:
    if span <= timedelta(hours=2):
        return "raw"
    if span <= timedelta(hours=36):
        return "5m"
    return "1h"


def _epoch(col):
    if engine.dialect.name == "mysql":
        return func.unix_timestamp(col, type_=Integer)
    return cast(func.strftime("%s", col), Integer)      # sqlite (chạy test)


@router.get("", response_model=TelemetrySeries)
def query_telemetry(device_id: int,
                    from_: datetime | None = Query(None, alias="from"),
                    to: datetime | None = None,
                    interval: Interval = "auto",
                    s: Session = Depends(get_db), actor: Actor = Depends(any_user)):
    """Chuỗi thời gian mực nước, lưu lượng, bơm (tự gộp theo mốc khi khoảng thời gian dài)"""
    dev = get_device_in_scope(s, actor, device_id)
    start, end = _resolve_range(from_, to, MAX_RANGE)
    if interval == "auto":
        interval = _auto_interval(end - start)
    if interval == "raw" and end - start > MAX_RAW_RANGE:
        raise InvalidInput("Dữ liệu thô chỉ cho khoảng tối đa 6 giờ; hãy chọn interval 1m/5m/15m/1h")

    cond = (Telemetry.device_id == dev.id, Telemetry.ts >= start, Telemetry.ts < end)
    if interval == "raw":
        rows = s.execute(select(Telemetry.ts, Telemetry.level_pct, Telemetry.flow_lpm,
                                Telemetry.flow_total_l, Telemetry.pump_on)
                         .where(*cond).order_by(Telemetry.ts).limit(RAW_LIMIT)).all()
        points = [TelemetryPoint(ts=_utc(r.ts), level_pct=r.level_pct, flow_lpm=r.flow_lpm,
                                 flow_total_l=r.flow_total_l, pump_on=_b(r.pump_on)) for r in rows]
    else:
        # literal_column: hằng số nằm trong SQL để MySQL (ONLY_FULL_GROUP_BY) thấy SELECT và GROUP BY giống nhau.
        # An toàn vì giá trị lấy từ bảng BUCKET_SECONDS, không phải từ người dùng.
        size = literal_column(str(BUCKET_SECONDS[interval]), type_=Integer)
        bucket = ((_epoch(Telemetry.ts) // size) * size).label("bucket")
        rows = s.execute(select(bucket, func.avg(Telemetry.level_pct), func.avg(Telemetry.flow_lpm),
                                func.max(Telemetry.flow_total_l), func.max(Telemetry.pump_on),
                                func.count())
                         .where(*cond).group_by(bucket).order_by(bucket)).all()
        points = [TelemetryPoint(ts=datetime.fromtimestamp(int(r[0]), tz=timezone.utc),
                                 level_pct=_f(r[1]), flow_lpm=_f(r[2]), flow_total_l=_f(r[3]),
                                 pump_on=_b(r[4]), n=int(r[5])) for r in rows]
    return TelemetrySeries(device_id=dev.id, device_type=dev.type, interval=interval, start=_utc(start),
                           end=_utc(end), points=points)


@router.get("/latest", response_model=LatestOut | None)
def latest(device_id: int, s: Session = Depends(get_db), actor: Actor = Depends(any_user)):
    """Mẫu telemetry mới nhất của thiết bị"""
    dev = get_device_in_scope(s, actor, device_id)
    row = s.scalars(select(Telemetry).where(Telemetry.device_id == dev.id)
                    .order_by(Telemetry.ts.desc(), Telemetry.id.desc()).limit(1)).first()
    if row is None:
        return None
    return LatestOut(ts=_utc(row.ts), received_at=_utc(row.received_at), device_type=dev.type,
                     distance_cm=row.distance_cm, level_pct=row.level_pct, flow_lpm=row.flow_lpm,
                     flow_total_l=row.flow_total_l, pump_on=row.pump_on, rssi=row.rssi)


def _csv_safe(value: str) -> str:
    # Chống CSV/formula injection khi mở bằng Excel
    return "'" + value if value and value[0] in "=+-@\t\r" else value


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _cell(value):
    return "" if value is None else value


@router.get("/export")
def export_csv(device_id: int,
               from_: datetime | None = Query(None, alias="from"),
               to: datetime | None = None,
               s: Session = Depends(get_db),
               actor: Actor = Depends(require_roles("Admin", "Operator"))):
    """Xuất CSV (tối đa 31 ngày, có ghi audit)"""
    dev = get_device_in_scope(s, actor, device_id)
    start, end = _resolve_range(from_, to, MAX_EXPORT_RANGE)
    write_audit(s, actor.id, "telemetry.export", "device", dev.id, actor.ip, f"{_iso(start)}..{_iso(end)}")
    s.commit()
    dev_id, code = dev.id, dev.device_code
    columns = [Telemetry.ts, Telemetry.received_at, Telemetry.boot_id, Telemetry.seq, Telemetry.distance_cm,
               Telemetry.level_pct, Telemetry.flow_lpm, Telemetry.flow_total_l, Telemetry.pump_on, Telemetry.rssi]

    def generate():
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["ts", "received_at", "boot_id", "seq", "distance_cm", "level_pct", "flow_lpm",
                    "flow_total_l", "pump_on", "rssi"])
        with SessionLocal() as qs:      # phiên riêng: phiên của request có thể đã đóng khi đang stream
            stmt = (select(*columns).where(Telemetry.device_id == dev_id, Telemetry.ts >= start,
                                           Telemetry.ts < end).order_by(Telemetry.ts)
                    .execution_options(yield_per=1000))
            for r in qs.execute(stmt):
                w.writerow([_iso(r.ts), _iso(r.received_at), _csv_safe(r.boot_id), r.seq, _cell(r.distance_cm),
                            _cell(r.level_pct), _cell(r.flow_lpm), _cell(r.flow_total_l),
                            "" if r.pump_on is None else int(r.pump_on), _cell(r.rssi)])
                if buf.tell() > 64_000:
                    yield buf.getvalue()
                    buf.seek(0)
                    buf.truncate(0)
        yield buf.getvalue()

    name = f"{code}_{start:%Y%m%d%H%M}_{end:%Y%m%d%H%M}.csv"
    return StreamingResponse(generate(), media_type="text/csv",
                             headers={"Content-Disposition": f'attachment; filename="{name}"'})
