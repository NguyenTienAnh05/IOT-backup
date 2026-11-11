from sqlalchemy.orm import Session

from .models import AuditLog


def write_audit(s: Session, user_id: int | None, action: str, target_type: str,
                target_id: int | str, ip: str, detail: str = "") -> None:
    """Chỉ add vào session; người gọi commit cùng giao dịch với thao tác chính."""
    s.add(AuditLog(user_id=user_id, action=action, target_type=target_type,
                   target_id=str(target_id), ip=ip[:45], detail=detail[:512]))
