"""Tạo tài khoản (dùng để tạo Admin đầu tiên và 3 tài khoản mẫu cho demo).
Chạy từ backend/:  python -m scripts.create_user --email admin@example.vn --role Admin --name "Quản trị"
Mật khẩu hỏi khi chạy (hoặc biến môi trường WMS_USER_PASSWORD). Không đưa mật khẩu vào repo.
"""
import argparse
import getpass
import os
import sys

from app import accounts
from app.db import Base, SessionLocal, engine
from app.lifecycle import Conflict

ap = argparse.ArgumentParser()
ap.add_argument("--email", required=True)
ap.add_argument("--role", choices=accounts.ROLES, required=True)
ap.add_argument("--name", default="")
args = ap.parse_args()

password = os.environ.get("WMS_USER_PASSWORD")
if not password:
    password = getpass.getpass("Mật khẩu: ")
    if password != getpass.getpass("Nhập lại: "):
        sys.exit("Hai lần nhập không khớp")

Base.metadata.create_all(engine)
with SessionLocal() as s:
    try:
        u = accounts.create_user(s, email=args.email, password=password, full_name=args.name,
                                 role=args.role, actor_id=None, ip="cli")
        print(f"Đã tạo {u.email} ({u.role}), id={u.id}")
    except (Conflict, accounts.InvalidInput) as e:
        sys.exit(str(e))
