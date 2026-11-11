from sqlalchemy import select
from sqlalchemy.orm import Session

from .deps import Actor
from .lifecycle import NotFound
from .models import Device, UserDevice


def get_device_in_scope(s: Session, actor: Actor, device_id: int) -> Device:
    """Admin thấy mọi thiết bị; Operator/Viewer chỉ thiết bị được gán.
    Không tồn tại và ngoài phạm vi trả cùng một lỗi 404 để không lộ sự tồn tại (S1)."""
    dev = s.get(Device, device_id)
    if dev is None:
        raise NotFound("Không tìm thấy thiết bị")
    if actor.role != "Admin":
        assigned = s.scalars(select(UserDevice.user_id).where(
            UserDevice.user_id == actor.id, UserDevice.device_id == device_id)).first()
        if assigned is None:
            raise NotFound("Không tìm thấy thiết bị")
    return dev
