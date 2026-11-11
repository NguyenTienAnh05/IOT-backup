from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

from .config import settings

ALGORITHM = "HS256"
_dummy_hash: bytes | None = None


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=settings.bcrypt_rounds)).decode()


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except ValueError:      # ví dụ mật khẩu > 72 byte
        return False


def dummy_verify(password: str) -> None:
    """Tốn thời gian như một lần kiểm tra thật, để không lộ email nào tồn tại qua độ trễ."""
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = bcrypt.hashpw(b"dummy", bcrypt.gensalt(rounds=settings.bcrypt_rounds))
    try:
        bcrypt.checkpw(password.encode(), _dummy_hash)
    except ValueError:
        pass


def create_token(user_id: int, token_version: int) -> tuple[str, int]:
    now = datetime.now(timezone.utc)
    ttl = settings.jwt_ttl_minutes
    payload = {"sub": str(user_id), "tv": token_version, "iat": now, "exp": now + timedelta(minutes=ttl)}
    return jwt.encode(payload, settings.jwt_secret, algorithm=ALGORITHM), ttl * 60


def decode_token(token: str) -> dict:
    return jwt.decode(token, settings.jwt_secret, algorithms=[ALGORITHM], options={"require": ["exp", "sub"]})
