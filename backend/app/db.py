from contextlib import contextmanager
from datetime import datetime, timezone

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import settings

if settings.is_sqlite:
    # check_same_thread=False: backend dùng nhiều thread (MQTT, watcher, request), mỗi kết nối chỉ một thread dùng tại một thời điểm.
    # timeout: thread ghi đến sau đợi tối đa 15 giây thay vì báo "database is locked" ngay.
    _connect_args = {"timeout": 15, "check_same_thread": False}
elif settings.database_url.startswith("mysql"):
    _connect_args = {"init_command": "SET time_zone='+00:00'"}
else:
    _connect_args = {}
engine = create_engine(settings.database_url, pool_pre_ping=True, pool_recycle=1800,
                       connect_args=_connect_args)

if settings.is_sqlite:
    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_connection, _record):
        cur = dbapi_connection.cursor()
        cur.execute("PRAGMA journal_mode=WAL")       # người đọc không chặn người ghi
        cur.execute("PRAGMA synchronous=NORMAL")     # an toàn với WAL, nhanh hơn FULL
        cur.execute("PRAGMA foreign_keys=ON")        # SQLite mặc định KHÔNG thực thi khóa ngoại
        cur.close()
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def utcnow() -> datetime:
    """Thời gian UTC dạng naive; toàn bộ DB lưu UTC."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


@contextmanager
def session_scope():
    s = SessionLocal()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()
