from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import lifecycle
from ..deps import Actor, any_user, get_db, require_roles
from ..models import Device, Site, UserDevice

router = APIRouter(prefix="/api/sites", tags=["sites"])
admin_only = require_roles("Admin")


class SiteCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=255)


class SiteNode(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    device_code: str
    type: str
    state: str
    online: bool


class SiteOut(BaseModel):
    id: int
    name: str
    description: str
    devices: list[SiteNode]


@router.get("", response_model=list[SiteOut])
def list_sites(s: Session = Depends(get_db), actor: Actor = Depends(any_user)):
    """Danh sách site kèm các node bồn và node ống trong site (Operator và Viewer chỉ thấy node được gán)"""
    nodes = select(Device).where(Device.site_id.is_not(None)).order_by(Device.id)
    if actor.role != "Admin":
        nodes = nodes.where(Device.id.in_(select(UserDevice.device_id).where(UserDevice.user_id == actor.id)))
    by_site: dict[int, list[Device]] = {}
    for d in s.scalars(nodes):
        by_site.setdefault(d.site_id, []).append(d)
    sites = select(Site).order_by(Site.id)
    if actor.role != "Admin":
        sites = sites.where(Site.id.in_(list(by_site)))
    return [SiteOut(id=x.id, name=x.name, description=x.description,
                    devices=[SiteNode.model_validate(d) for d in by_site.get(x.id, [])]) for x in s.scalars(sites)]


@router.post("", response_model=SiteOut, status_code=201)
def create_site(body: SiteCreate, s: Session = Depends(get_db), actor: Actor = Depends(admin_only)):
    """Tạo site (nhóm một node bồn và một node ống thành một hệ thống)"""
    site = lifecycle.create_site(s, name=body.name, description=body.description, actor_id=actor.id, ip=actor.ip)
    return SiteOut(id=site.id, name=site.name, description=site.description, devices=[])
