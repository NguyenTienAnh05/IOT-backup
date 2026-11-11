import pathlib

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_DEFAULT_DB = pathlib.Path(__file__).resolve().parents[1] / "wms.db"      # backend/wms.db, không phụ thuộc thư mục đang đứng


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Trống = SQLite ở backend/wms.db (khỏi cài gì, tự tạo bảng). MySQL: mysql+pymysql://user:pass@host:3306/wms?charset=utf8mb4
    database_url: str = Field(default="", validate_default=True)  # trống = SQLite backend/wms.db; hoặc URL MySQL
    # Schema MySQL do database/migrations tạo. SQLite tự tạo bảng khi khởi động nên không cần cờ này
    auto_create_tables: bool = False  # chỉ bật khi dev với MySQL rỗng và tài khoản có quyền CREATE
    telemetry_retention_days: int = 90  # SQLite: app tự xóa telemetry cũ; MySQL đã có EVENT trong migration 002
    mqtt_host: str = "localhost"
    mqtt_port: int = 1883
    mqtt_username: str = "backend"
    mqtt_password: str = ""
    mqtt_tls: bool = False          # bật khi Mosquitto đã cấu hình TLS (cổng 8883)
    mqtt_ca_file: str = ""
    mqtt_client_id: str = "wms-backend"

    # "dynsec": quản lý tài khoản thiết bị qua Mosquitto Dynamic Security; "none": chỉ ghi log (dev)
    broker_admin: str = "none"  # none = chỉ ghi log (dev); dynsec = Mosquitto Dynamic Security
    # Xác thực
    jwt_secret: str = ""            # bắt buộc, >= 32 ký tự (xem .env.example)
    jwt_ttl_minutes: int = 30  # thời hạn JWT
    bcrypt_rounds: int = 12  # độ tốn kém băm mật khẩu
    min_password_len: int = 8  # độ dài mật khẩu tối thiểu
    login_max_attempts: int = 5     # sai liên tiếp quá số này thì khóa tạm (S6)
    lockout_minutes: int = 15  # thời gian khóa tạm sau khi đăng nhập sai quá số lần
    # Lệnh bơm
    command_timeout_s: int = 5          # không có ack sau số giây này thì ghi timeout
    pump_default_duration_s: int = 60  # thời gian bơm mặc định của lệnh, giây
    pump_max_duration_s: int = 120      # khớp pump_max_run_s trên thiết bị; thiết bị vẫn tự giới hạn

    # WebSocket /ws
    ws_allowed_origins: str = ""        # danh sách Origin cho phép, cách nhau bằng dấu phẩy; rỗng = không kiểm tra (dev)
    ws_auth_timeout_s: float = 5        # thời gian chờ thông điệp auth đầu tiên
    ws_revalidate_s: float = 30         # chu kỳ kiểm tra lại phiên và phạm vi thiết bị của kết nối đang mở
    ws_max_connections: int = 200  # tổng số kết nối WebSocket
    ws_max_per_user: int = 5  # số kết nối WebSocket tối đa mỗi người
    ws_queue_size: int = 200            # hàng đợi gửi mỗi kết nối; đầy thì ngắt (máy khách quá chậm)

    # Quy tắc xử lý (mục 4.3 của khung)
    max_payload_bytes: int = 2048  # bản tin MQTT lớn hơn thì bỏ
    ts_tolerance_s: int = 300       # ts lệch quá ±5 phút thì loại
    heartbeat_timeout_s: int = 90   # mất heartbeat quá 90s thì offline
    # Giới hạn tần suất theo thiết bị; đủ rộng để cho phép gửi bù ~100 mẫu sau khi mất mạng
    rate_limit_msgs: int = 100  # bản tin / cửa sổ / thiết bị; đủ rộng để nhận ~100 mẫu gửi bù
    rate_limit_window_s: int = 10  # độ dài cửa sổ giới hạn tần suất, giây
    @field_validator("database_url")
    @classmethod
    def _default_database(cls, value: str) -> str:
        return value.strip() or f"sqlite:///{_DEFAULT_DB.as_posix()}"

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")

    def require_jwt_secret(self) -> None:
        if len(self.jwt_secret) < 32:
            raise RuntimeError("JWT_SECRET chưa đặt hoặc quá ngắn (cần >= 32 ký tự)")


settings = Settings()
