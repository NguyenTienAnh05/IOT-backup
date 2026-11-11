"""Quản lý tài khoản thiết bị trên Mosquitto (Cách 1 ở mục 5: Dynamic Security).

Cần phía broker (TV3): bật plugin mosquitto_dynamic_security, và tài khoản `backend`
(MQTT_USERNAME) có quyền admin dynsec. Kiểm tra tài liệu theo phiên bản Mosquitto đang dùng:
tên ACL type, và việc hỗ trợ %u trong topic của role.
Cách 2 (password_file + restart) có thể cài thêm như một lớp BrokerAdmin khác.
"""
import json
import logging
import threading
import uuid

import paho.mqtt.client as mqtt

from .config import settings

log = logging.getLogger("broker_admin")


class BrokerError(Exception):
    pass


class BrokerAdmin:
    def start(self) -> None: ...
    def stop(self) -> None: ...
    def create_client(self, username: str, password: str) -> None: raise NotImplementedError
    def set_enabled(self, username: str, enabled: bool) -> None: raise NotImplementedError
    def delete_client(self, username: str) -> None: raise NotImplementedError


class NoopBrokerAdmin(BrokerAdmin):
    """Dev: không đụng broker. Thiết bị thật sẽ KHÔNG đăng nhập được bằng credential cấp ra."""

    def start(self) -> None:
        log.warning("BROKER_ADMIN=none: không tạo/xóa tài khoản trên broker (chỉ dùng khi dev)")

    def create_client(self, username, password): log.info("[noop] create_client %s", username)
    def set_enabled(self, username, enabled): log.info("[noop] set_enabled %s=%s", username, enabled)
    def delete_client(self, username): log.info("[noop] delete_client %s", username)


class DynSecAdmin(BrokerAdmin):
    TOPIC = "$CONTROL/dynamic-security/v1"
    ROLE = "wms-device"
    # (acltype, topic): %u = username = deviceId, nên 1 role dùng cho mọi thiết bị
    DEVICE_ACLS = [
        ("publishClientSend", "wms/%u/telemetry"),
        ("publishClientSend", "wms/%u/status"),
        ("publishClientSend", "wms/%u/ack"),
        ("publishClientReceive", "wms/%u/cmd"),
        ("publishClientReceive", "wms/%u/config"),
        ("subscribeLiteral", "wms/%u/cmd"),
        ("subscribeLiteral", "wms/%u/config"),
    ]
    TIMEOUT_S = 5.0

    def __init__(self) -> None:
        self._client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,
                                   client_id=f"{settings.mqtt_client_id}-dynsec")
        self._client.username_pw_set(settings.mqtt_username, settings.mqtt_password)
        if settings.mqtt_tls:
            self._client.tls_set(ca_certs=settings.mqtt_ca_file or None)
        self._client.reconnect_delay_set(min_delay=1, max_delay=30)
        self._client.on_connect = self._on_connect
        self._client.on_subscribe = self._on_subscribe
        self._client.on_message = self._on_message
        self._ready = threading.Event()          # đã subscribe xong topic response
        self._pending: dict[str, tuple[threading.Event, dict]] = {}
        self._lock = threading.Lock()
        self._role_ready = False

    def start(self) -> None:
        self._client.connect_async(settings.mqtt_host, settings.mqtt_port, keepalive=30)
        self._client.loop_start()

    def stop(self) -> None:
        self._client.disconnect()
        self._client.loop_stop()

    # -- callbacks (thread của paho) --
    def _on_connect(self, client, userdata, flags, reason_code, properties):
        self._ready.clear()
        if reason_code.is_failure:
            log.error("dynsec connect failed: %s", reason_code)
            return
        client.subscribe(f"{self.TOPIC}/response", qos=1)

    def _on_subscribe(self, client, userdata, mid, reason_codes, properties):
        self._ready.set()

    def _on_message(self, client, userdata, msg):
        try:
            responses = json.loads(msg.payload).get("responses", [])
        except (ValueError, AttributeError):
            return
        for r in responses:
            with self._lock:
                entry = self._pending.get(r.get("correlationData"))
            if entry:
                entry[1].update(r)
                entry[0].set()

    # -- gửi lệnh và chờ phản hồi --
    def _send(self, command: dict) -> None:
        if not self._ready.wait(self.TIMEOUT_S):
            raise BrokerError("không kết nối được tới broker (dynsec)")
        cid = uuid.uuid4().hex
        event, box = threading.Event(), {}
        with self._lock:
            self._pending[cid] = (event, box)
        try:
            payload = json.dumps({"commands": [{**command, "correlationData": cid}]})
            self._client.publish(self.TOPIC, payload, qos=1)
            if not event.wait(self.TIMEOUT_S):
                raise BrokerError("broker không phản hồi lệnh dynsec")
        finally:
            with self._lock:
                self._pending.pop(cid, None)
        if box.get("error"):
            raise BrokerError(str(box["error"]))

    def _send_ignoring(self, command: dict, *phrases: str) -> None:
        try:
            self._send(command)
        except BrokerError as e:
            if not any(p in str(e).lower() for p in phrases):
                raise

    def _ensure_role(self) -> None:
        if self._role_ready:
            return
        self._send_ignoring({"command": "createRole", "rolename": self.ROLE}, "already exists")
        for acltype, topic in self.DEVICE_ACLS:
            self._send_ignoring({"command": "addRoleACL", "rolename": self.ROLE, "acltype": acltype,
                                 "topic": topic, "allow": True, "priority": 0}, "already exists")
        self._role_ready = True

    # -- API cho lifecycle --
    def create_client(self, username: str, password: str) -> None:
        self._ensure_role()
        try:
            self._send({"command": "createClient", "username": username, "password": password,
                        "roles": [{"rolename": self.ROLE}]})
        except BrokerError as e:
            if "already exists" not in str(e).lower():
                raise
            # Tài khoản mồ côi từ lần cấp lỗi trước: đặt lại mật khẩu mới
            self._send({"command": "setClientPassword", "username": username, "password": password})
            self._send({"command": "enableClient", "username": username})

    def set_enabled(self, username: str, enabled: bool) -> None:
        # disableClient ngắt kết nối đang có của client
        self._send({"command": "enableClient" if enabled else "disableClient", "username": username})

    def delete_client(self, username: str) -> None:
        # deleteClient cũng ngắt kết nối ngay; không tìm thấy = coi như đã xóa
        self._send_ignoring({"command": "deleteClient", "username": username}, "not found")


_instance: BrokerAdmin | None = None


def get_broker_admin() -> BrokerAdmin:
    global _instance
    if _instance is None:
        _instance = DynSecAdmin() if settings.broker_admin == "dynsec" else NoopBrokerAdmin()
    return _instance
