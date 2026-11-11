from fastapi import FastAPI
from fastapi.responses import JSONResponse

from .broker_admin import BrokerError
from .lifecycle import Conflict, InvalidReference, InvalidTransition, NotFound


class InvalidInput(Exception):
    pass


class InvalidCredentials(Exception):
    def __init__(self):
        super().__init__("Email hoặc mật khẩu không đúng")   # cùng một thông báo cho mọi trường hợp sai


class AccountLocked(Exception):
    def __init__(self, minutes: int):
        super().__init__(f"Tài khoản tạm khóa, thử lại sau {minutes} phút")
        self.minutes = minutes


class AccountDisabled(Exception):
    def __init__(self):
        super().__init__("Tài khoản đã bị vô hiệu hóa")


class PublishError(Exception):
    """Không đưa được bản tin tới broker."""


class SelfLockout(Exception):
    def __init__(self):
        super().__init__("Không thể tự khóa hoặc hạ quyền chính mình")


def install_error_handlers(app: FastAPI) -> None:
    def register(exc_type, status, headers=None):
        async def _handler(request, exc):
            return JSONResponse(status_code=status, content={"detail": str(exc)},
                                headers=headers(exc) if headers else None)
        app.add_exception_handler(exc_type, _handler)

    register(NotFound, 404)
    register(Conflict, 409)
    register(InvalidTransition, 409)
    register(SelfLockout, 409)
    register(InvalidInput, 422)
    register(InvalidReference, 422)
    register(AccountDisabled, 403)
    register(BrokerError, 502)
    register(PublishError, 502)
    register(InvalidCredentials, 401, lambda e: {"WWW-Authenticate": "Bearer"})
    register(AccountLocked, 429, lambda e: {"Retry-After": str(e.minutes * 60)})
