import asyncio
import contextlib
import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, WebSocket

from ..config import settings
from ..db import utcnow
from ..deps import Actor, require_roles
from ..realtime import EVENT_ROLES, Client, Identity, _iso, hub, load_identity

log = logging.getLogger("ws")
router = APIRouter(tags=["realtime"])
MAX_AUTH_MESSAGE = 4096


def _origin_ok(ws: WebSocket) -> bool:
    allowed = [o.strip() for o in settings.ws_allowed_origins.split(",") if o.strip()]
    return not allowed or ws.headers.get("origin") in allowed


def _bearer(ws: WebSocket) -> str | None:
    scheme, _, token = ws.headers.get("authorization", "").partition(" ")
    return token.strip() or None if scheme.lower() == "bearer" else None


async def _reject(ws: WebSocket, code: int, error_code: str, message: str) -> None:
    with contextlib.suppress(Exception):
        await ws.send_text(json.dumps({"event": "error", "data": {"code": error_code, "message": message},
                                       "sent_at": _iso(utcnow())}, ensure_ascii=False))
        await ws.close(code=code, reason=error_code)


async def _authenticate(ws: WebSocket) -> Identity | None:
    """Trình duyệt không đặt được header Authorization cho WebSocket và không nên đưa token lên URL (lộ trong log),
    nên máy khách gửi {"type":"auth","token":...} ngay sau khi kết nối. Máy khách khác có thể dùng header Bearer."""
    token = _bearer(ws)
    if token is None:
        try:
            text = await asyncio.wait_for(ws.receive_text(), timeout=settings.ws_auth_timeout_s)
            msg = json.loads(text) if len(text) <= MAX_AUTH_MESSAGE else None
            if not isinstance(msg, dict) or msg.get("type") != "auth" or not isinstance(msg.get("token"), str):
                raise ValueError
            token = msg["token"]
        except Exception:
            await _reject(ws, 4401, "unauthorized", 'Cần gửi {"type":"auth","token":"<JWT>"} ngay sau khi kết nối')
            return None
    ident = await asyncio.to_thread(load_identity, token)
    if ident is None:
        await _reject(ws, 4401, "unauthorized", "Token không hợp lệ, đã hết hạn hoặc đã bị thu hồi")
    return ident


@router.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    """Kết nối thời gian thực, xác thực bằng JWT (hợp đồng chi tiết: docs/websocket.md)"""
    if not _origin_ok(websocket):
        await websocket.close(code=1008)
        return
    await websocket.accept()
    if not hub.begin_pending():
        await _reject(websocket, 1013, "overloaded", "Máy chủ đang quá tải")
        return
    try:
        ident = await _authenticate(websocket)
    finally:
        hub.end_pending()
    if ident is None:
        return
    if not hub.can_accept(ident.user_id):
        await _reject(websocket, 1013, "too_many_connections", "Vượt số kết nối cho phép")
        return

    client = Client(websocket, ident, asyncio.get_running_loop())
    client.send_event("ready", {
        "user_id": ident.user_id, "role": ident.role,
        "expires_at": _iso(datetime.fromtimestamp(ident.exp, tz=timezone.utc)),
        "events": [e for e, roles in EVENT_ROLES.items() if ident.role in roles],
        "device_ids": None if ident.devices is None else sorted(ident.devices),    # None = mọi thiết bị
    })
    hub.add(client)         # sau khi xếp 'ready' vào hàng đợi: ready luôn là thông điệp đầu tiên
    tasks = [asyncio.create_task(c) for c in (client.sender(), client.receiver(), client.guard())]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in tasks:
            t.cancel()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        hub.remove(client)
        for r in results:
            if isinstance(r, Exception) and not isinstance(r, asyncio.CancelledError):
                log.debug("ws task kết thúc: %r", r)
        with contextlib.suppress(Exception):
            if client.close_error:
                code, message = client.close_error
                await websocket.send_text(json.dumps({"event": "error", "data": {"code": code, "message": message},
                                                      "sent_at": _iso(utcnow())}, ensure_ascii=False))
            await websocket.close(code=client.close_code, reason=(client.close_error or ("",))[0])


@router.get("/api/metrics/latency")
def latency_stats(actor: Actor = Depends(require_roles("Admin"))):
    """Độ trễ telemetry (ms) trên các mẫu gần nhất: device_to_backend, backend_to_push, end_to_push."""
    return hub.stats.summary()


@router.delete("/api/metrics/latency", status_code=204)
def reset_latency_stats(actor: Actor = Depends(require_roles("Admin"))):
    """Xóa bộ đếm độ trễ"""
    hub.stats.reset()
