from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import accounts, security
from ..deps import Actor, any_user, get_db
from ..schemas import UserOut

router = APIRouter(prefix="/api", tags=["auth"])


class LoginIn(BaseModel):
    email: str = Field(max_length=255)
    password: str = Field(max_length=128)


class ChangePasswordIn(BaseModel):
    current_password: str = Field(max_length=128)
    new_password: str = Field(max_length=128)


class ProfileIn(BaseModel):
    full_name: str = Field(max_length=128)


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserOut


def _token_out(user) -> TokenOut:
    token, ttl = security.create_token(user.id, user.token_version)
    return TokenOut(access_token=token, expires_in=ttl, user=UserOut.model_validate(user))


@router.post("/auth/login", response_model=TokenOut)
def login(body: LoginIn, request: Request, s: Session = Depends(get_db)):
    """Đăng nhập, trả JWT (sai 5 lần liên tiếp thì khóa tạm 15 phút)"""
    ip = request.client.host if request.client else ""
    return _token_out(accounts.authenticate(s, body.email, body.password, ip))


@router.post("/auth/logout", status_code=204)
def logout(s: Session = Depends(get_db), actor: Actor = Depends(any_user)):
    """Đăng xuất, hủy mọi phiên của tài khoản"""
    accounts.logout(s, actor.id, actor.ip)      # hủy mọi phiên của tài khoản này
    return Response(status_code=204)


@router.post("/auth/change-password", response_model=TokenOut)
def change_password(body: ChangePasswordIn, s: Session = Depends(get_db), actor: Actor = Depends(any_user)):
    """Đổi mật khẩu, trả token mới (token cũ bị hủy)"""
    user = accounts.change_password(s, actor.id, body.current_password, body.new_password, actor.ip)
    return _token_out(user)                     # token cũ đã bị hủy, cấp token mới


@router.get("/me", response_model=UserOut)
def me(s: Session = Depends(get_db), actor: Actor = Depends(any_user)):
    """Thông tin tài khoản đang đăng nhập"""
    return accounts.get_user(s, actor.id)


@router.patch("/me", response_model=UserOut)
def update_me(body: ProfileIn, s: Session = Depends(get_db), actor: Actor = Depends(any_user)):
    """Sửa họ tên của chính mình"""
    return accounts.update_profile(s, actor.id, body.full_name, actor.ip)
