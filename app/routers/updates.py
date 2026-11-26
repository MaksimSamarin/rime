from pathlib import Path
import os

from fastapi import APIRouter, Depends, HTTPException, Response,Header
import secrets
from pydantic import BaseModel, Field

from app import __version__
from app.models.admin import Admin
from config import SQLALCHEMY_DATABASE_URL
from hy2bridge.updates import Updates
from update_runtime.releases import UpdateError
from update_runtime.paths import sqlite_database,update_directory

router = APIRouter(prefix='/api/system/updates', tags=['Updates'])
database = sqlite_database(SQLALCHEMY_DATABASE_URL)
service = Updates(update_directory(SQLALCHEMY_DATABASE_URL), __version__,
                  database if database is not None and database.is_absolute() else None,
                  supported=database is not None and database.is_absolute())
from app import scheduler
from update_runtime import readiness
readiness.register(scheduler)


@router.get('/ready')
def ready(response: Response,authorization: str=Header(default='')):
    response.headers['Cache-Control']='no-store'
    try:
        path=service.directory/'.health-token'
        if path.is_symlink() or path.stat().st_size>256:raise ValueError()
        expected=path.read_text().strip()
        if len(expected)<32 or not secrets.compare_digest(authorization,'Bearer '+expected):raise ValueError()
    except (OSError,ValueError):
        raise HTTPException(401,detail='Invalid readiness token') from None
    value=readiness.snapshot()
    if not value['ready']:raise HTTPException(503,detail='Application not ready')
    return value


class UpdateRequest(BaseModel):
    version: str = Field(pattern=r'^\d+\.\d+\.\d+(?:-rc\.?\d+)?$')


class RollbackRequest(BaseModel):
    confirmation: str


class DowngradeRequest(BaseModel):
    version: str = Field(pattern=r'^\d+\.\d+\.\d+(?:-rc\.?\d+)?$')
    confirmation: str


@router.post('/downgrade/prepare')
def prepare_downgrade(payload: DowngradeRequest,response: Response,admin=Depends(Admin.check_sudo_admin)):
    if payload.confirmation!='restart-qualified-cores':raise HTTPException(409,detail='downgrade_confirmation_required')
    from app.utils.downgrade import prepare
    return invoke(response,prepare,payload.version,service.directory)


@router.post('/downgrade/cancel')
def cancel_downgrade(response: Response,admin=Depends(Admin.check_sudo_admin)):
    from app.utils.downgrade import cancel
    return invoke(response,cancel,service.directory)


def invoke(response, function, *args):
    response.headers['Cache-Control'] = 'no-store'
    try:
        return function(*args)
    except UpdateError as error:
        raise HTTPException(409, detail=error.code) from None
    except BlockingIOError:
        raise HTTPException(409,detail='update_running') from None


@router.get('')
def status(response: Response, admin=Depends(Admin.check_sudo_admin)):
    return invoke(response, service.status)


@router.post('/check')
def check(response: Response, admin=Depends(Admin.check_sudo_admin)):
    return invoke(response, service.check)


@router.post('')
def update(payload: UpdateRequest, response: Response, admin=Depends(Admin.check_sudo_admin)):
    return invoke(response, service.enqueue, payload.version)


@router.post('/cancel')
def cancel(response: Response, admin=Depends(Admin.check_sudo_admin)):
    return invoke(response, service.cancel)


@router.post('/rollback')
def rollback(payload: RollbackRequest, response: Response, admin=Depends(Admin.check_sudo_admin)):
    return invoke(response, service.enqueue_rollback, payload.confirmation)
