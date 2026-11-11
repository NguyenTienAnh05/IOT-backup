"""Hook sự kiện nội bộ. WebSocket gateway sẽ đăng ký callback ở đây: cb(event_type, payload)."""
import logging
from typing import Callable

log = logging.getLogger("events")
_callback: Callable[[str, dict], None] = lambda event, payload: None


def set_event_callback(cb: Callable[[str, dict], None]) -> None:
    global _callback
    _callback = cb


def emit(event: str, payload: dict) -> None:
    try:
        _callback(event, payload)
    except Exception:
        log.exception("event callback failed (%s)", event)
