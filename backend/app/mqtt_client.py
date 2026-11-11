import logging

import paho.mqtt.client as mqtt

from . import ingest
from .config import settings
from .errors import PublishError

log = logging.getLogger("mqtt")


SUBSCRIPTIONS = [("wms/+/telemetry", 1), ("wms/+/status", 1), ("wms/+/ack", 1)]


class MqttSubscriber:
    def __init__(self) -> None:
        # client_id cố định + clean_session=False: broker giữ QoS1 trong lúc backend tạm tắt
        self.client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=settings.mqtt_client_id,
            clean_session=False,
        )
        self.client.username_pw_set(settings.mqtt_username, settings.mqtt_password)
        if settings.mqtt_tls:
            self.client.tls_set(ca_certs=settings.mqtt_ca_file or None)
        self.client.reconnect_delay_set(min_delay=1, max_delay=30)
        self.client.on_connect = self._on_connect
        self.client.on_disconnect = self._on_disconnect
        self.client.on_message = self._on_message

    def start(self) -> None:
        self.client.connect_async(settings.mqtt_host, settings.mqtt_port, keepalive=30)
        self.client.loop_start()    # thread nền, tự reconnect

    def stop(self) -> None:
        self.client.disconnect()
        self.client.loop_stop()

    def publish(self, topic: str, payload: str, qos: int = 1, retain: bool = False) -> None:
        """Publish và chờ broker xác nhận (PUBACK) tối đa 2 giây; lỗi thì ném PublishError."""
        if not self.client.is_connected():
            raise PublishError("Backend chưa kết nối được broker MQTT")
        try:
            info = self.client.publish(topic, payload, qos=qos, retain=retain)
            if info.rc != mqtt.MQTT_ERR_SUCCESS:
                raise PublishError(f"Publish thất bại (rc={info.rc})")
            info.wait_for_publish(timeout=2.0)
        except (ValueError, RuntimeError) as e:
            raise PublishError(f"Publish thất bại: {e}")
        if not info.is_published():
            raise PublishError("Broker chưa xác nhận đã nhận lệnh")

    # Subscribe trong on_connect để tự đăng ký lại sau mỗi lần reconnect
    def _on_connect(self, client, userdata, flags, reason_code, properties) -> None:
        if reason_code.is_failure:
            log.error("MQTT connect failed: %s", reason_code)
            return
        log.info("MQTT connected to %s:%s", settings.mqtt_host, settings.mqtt_port)
        client.subscribe(SUBSCRIPTIONS)

    def _on_disconnect(self, client, userdata, disconnect_flags, reason_code, properties) -> None:
        log.warning("MQTT disconnected: %s (sẽ tự kết nối lại)", reason_code)

    def _on_message(self, client, userdata, msg) -> None:
        try:
            ingest.handle_message(msg.topic, msg.payload, retained=bool(msg.retain))
        except Exception:
            # Không để một bản tin lỗi làm chết thread mạng của paho
            log.exception("unhandled error processing topic=%s", msg.topic)


_instance: MqttSubscriber | None = None


def get_subscriber() -> MqttSubscriber:
    global _instance
    if _instance is None:
        _instance = MqttSubscriber()
    return _instance
