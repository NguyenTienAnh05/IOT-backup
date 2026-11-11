import logging
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI

from . import alerts as alert_engine
from . import events
from .broker_admin import get_broker_admin
from .commands import run_command_watcher
from .config import settings
from .db import Base, engine
from .errors import install_error_handlers
from .ingest import run_offline_watcher
from .mqtt_client import get_subscriber
from .retention import run_retention_watcher
from .realtime import hub
from .routers import alerts as alerts_router
from .routers import audit, auth, commands, devices, sites, telemetry, users
from .routers import config as config_router
from .routers import ws as ws_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.require_jwt_secret()       # không khởi động nếu thiếu khóa ký JWT
    if settings.is_sqlite or settings.auto_create_tables:   # SQLite tự tạo bảng; MySQL: schema do database/migrations tạo
        Base.metadata.create_all(engine)
    stop = threading.Event()
    events.set_event_callback(hub.publish)      # mọi sự kiện nội bộ được phát tới WebSocket
    subscriber = get_subscriber()
    alert_engine.set_publisher(subscriber)      # để alert engine gửi lệnh bơm tự động
    subscriber.start()
    broker_admin = get_broker_admin()
    broker_admin.start()
    threading.Thread(target=run_offline_watcher, args=(stop,), daemon=True).start()
    threading.Thread(target=run_command_watcher, args=(stop,), daemon=True).start()
    if settings.is_sqlite:              # MySQL đã có EVENT dọn telemetry (migration 002); SQLite thì app tự dọn
        threading.Thread(target=run_retention_watcher, args=(stop,), daemon=True).start()
    yield
    stop.set()
    events.set_event_callback(lambda event, payload: None)
    alert_engine.shutdown()
    broker_admin.stop()
    subscriber.stop()


app = FastAPI(title="WMS Backend", lifespan=lifespan)
install_error_handlers(app)
for r in (auth.router, users.router, sites.router, devices.router, commands.router, config_router.router, telemetry.router,
          alerts_router.router, audit.router, ws_router.router):
    app.include_router(r)


@app.get("/api/health")
def health():
    """Kiểm tra dịch vụ còn sống"""
    return {"status": "ok"}
