"""Giữ telemetry theo TELEMETRY_RETENTION_DAYS (mặc định 90 ngày) khi chạy SQLite.

MySQL đã có EVENT ev_telemetry_retention (database/migrations/002) nên không dùng module này. Câu lệnh
DELETE ... WHERE id IN (SELECT ... LIMIT n) hợp lệ trên SQLite, nhưng MySQL không cho LIMIT trong IN-subquery."""
import logging
import threading
from datetime import timedelta

from sqlalchemy import delete, select

from .config import settings
from .db import session_scope, utcnow
from .models import Telemetry

log = logging.getLogger("retention")


def purge_old_telemetry(days: int | None = None, batch: int = 20000) -> int:
    """Xóa telemetry cũ hơn 'days' ngày, từng lô để không giữ khóa ghi lâu. Trả về số dòng đã xóa."""
    cutoff = utcnow() - timedelta(days=settings.telemetry_retention_days if days is None else days)
    total = 0
    while True:
        with session_scope() as s:
            ids = select(Telemetry.id).where(Telemetry.ts < cutoff).limit(batch)
            deleted = s.execute(delete(Telemetry).where(Telemetry.id.in_(ids))).rowcount
        total += deleted
        if deleted < batch:
            return total


def run_retention_watcher(stop: threading.Event, interval_s: float = 3600.0) -> None:
    while True:                         # dọn ngay khi khởi động, rồi mỗi giờ
        try:
            removed = purge_old_telemetry()
            if removed:
                log.info("đã xóa %d bản ghi telemetry quá %d ngày", removed, settings.telemetry_retention_days)
        except Exception:
            log.exception("retention lỗi")
        if stop.wait(interval_s):
            return
