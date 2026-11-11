from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..deps import Actor, get_db, require_roles
from ..models import AuditLog, User

router = APIRouter(prefix="/api/audit-logs", tags=["audit"])


class AuditOut(BaseModel):
    id: int
    user_id: int | None
    user_email: str | None
    action: str
    target_type: str
    target_id: str
    ip: str
    detail: str      # có thể chứa chuỗi do người dùng nhập: frontend phải escape khi hiển thị
    created_at: datetime


class AuditPage(BaseModel):
    total: int
    items: list[AuditOut]


def _naive_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo else dt


@router.get("", response_model=AuditPage)
def list_audit(user_id: int | None = None, action: str | None = None,
               from_: datetime | None = Query(None, alias="from"), to: datetime | None = None,
               limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
               s: Session = Depends(get_db), actor: Actor = Depends(require_roles("Admin"))):
    """Nhật ký thao tác (lọc theo người, hành động, thời gian; có phân trang)"""
    conds = []
    if user_id is not None:
        conds.append(AuditLog.user_id == user_id)
    if action:
        conds.append(AuditLog.action == action)
    if from_:
        conds.append(AuditLog.created_at >= _naive_utc(from_))
    if to:
        conds.append(AuditLog.created_at < _naive_utc(to))

    total = s.scalar(select(func.count()).select_from(AuditLog).where(*conds)) or 0
    rows = s.execute(select(AuditLog, User.email).outerjoin(User, User.id == AuditLog.user_id)
                     .where(*conds).order_by(AuditLog.id.desc()).limit(limit).offset(offset)).all()
    items = [AuditOut(id=a.id, user_id=a.user_id, user_email=email, action=a.action,
                      target_type=a.target_type, target_id=a.target_id, ip=a.ip, detail=a.detail,
                      created_at=a.created_at.replace(tzinfo=timezone.utc)) for a, email in rows]
    return AuditPage(total=total, items=items)
