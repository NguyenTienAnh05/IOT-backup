from dataclasses import dataclass
from typing import Iterator

import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .db import SessionLocal
from .models import User
from .security import decode_token

_bearer = HTTPBearer(auto_error=False)


def get_db() -> Iterator[Session]:
    s = SessionLocal()
    try:
        yield s
    finally:
        s.close()


@dataclass
class Actor:
    id: int
    role: str
    ip: str


def current_actor(request: Request,
                  creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
                  s: Session = Depends(get_db)) -> Actor:
    unauthorized = HTTPException(401, "Chưa đăng nhập hoặc token không hợp lệ",
                                 headers={"WWW-Authenticate": "Bearer"})
    if creds is None:
        raise unauthorized
    try:
        claims = decode_token(creds.credentials)
        user = s.get(User, int(claims["sub"]))
    except (jwt.PyJWTError, ValueError, KeyError):
        raise unauthorized
    # token_version khác = đã đăng xuất / đổi mật khẩu / đổi quyền; disabled = bị khóa
    if user is None or user.status != "active" or user.token_version != claims.get("tv"):
        raise unauthorized
    return Actor(id=user.id, role=user.role, ip=request.client.host if request.client else "")


def require_roles(*roles: str):
    def dependency(actor: Actor = Depends(current_actor)) -> Actor:
        if actor.role not in roles:
            raise HTTPException(403, "Không đủ quyền")
        return actor
    return dependency


any_user = require_roles("Admin", "Operator", "Viewer")
