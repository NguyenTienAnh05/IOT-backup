from typing import Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import accounts
from ..deps import Actor, get_db, require_roles
from ..models import User
from ..schemas import UserOut

router = APIRouter(prefix="/api/users", tags=["users"])
admin_only = require_roles("Admin")

Role = Literal["Admin", "Operator", "Viewer"]


class UserCreate(BaseModel):
    email: str = Field(pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$", max_length=255)
    password: str = Field(max_length=128)
    full_name: str = Field(default="", max_length=128)
    role: Role


class UserUpdate(BaseModel):
    full_name: str | None = Field(default=None, max_length=128)
    role: Role | None = None
    status: Literal["active", "disabled"] | None = None
    unlock: bool = False        # Admin mở khóa tạm do đăng nhập sai


class DeviceAssign(BaseModel):
    device_ids: list[int] = Field(max_length=200)


@router.get("", response_model=list[UserOut])
def list_users(s: Session = Depends(get_db), actor: Actor = Depends(admin_only)):
    """Danh sách người dùng"""
    return s.scalars(select(User).order_by(User.id)).all()


@router.post("", response_model=UserOut, status_code=201)
def create_user(body: UserCreate, s: Session = Depends(get_db), actor: Actor = Depends(admin_only)):
    """Tạo tài khoản"""
    return accounts.create_user(s, email=body.email, password=body.password, full_name=body.full_name,
                                role=body.role, actor_id=actor.id, ip=actor.ip)


@router.patch("/{user_id}", response_model=UserOut)
def update_user(user_id: int, body: UserUpdate, s: Session = Depends(get_db),
                actor: Actor = Depends(admin_only)):
    """Sửa họ tên, vai trò, trạng thái; mở khóa tạm (unlock)"""
    return accounts.update_user(s, user_id, full_name=body.full_name, role=body.role, status=body.status,
                                unlock=body.unlock, actor_id=actor.id, ip=actor.ip)


@router.get("/{user_id}/devices", response_model=DeviceAssign)
def get_user_devices(user_id: int, s: Session = Depends(get_db), actor: Actor = Depends(admin_only)):
    """Thiết bị được gán cho người dùng"""
    return DeviceAssign(device_ids=accounts.get_user_device_ids(s, user_id))


@router.put("/{user_id}/devices", response_model=DeviceAssign)
def set_user_devices(user_id: int, body: DeviceAssign, s: Session = Depends(get_db),
                     actor: Actor = Depends(admin_only)):
    """Gán lại toàn bộ thiết bị cho người dùng (có hiệu lực với Operator và Viewer)"""
    ids = accounts.set_user_devices(s, user_id, body.device_ids, actor_id=actor.id, ip=actor.ip)
    return DeviceAssign(device_ids=ids)
