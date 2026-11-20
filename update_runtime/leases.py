"""Coordinate panel changes with host-side replacement through the data mount."""
import contextlib
import fcntl
import os
import json
import secrets
from pathlib import Path


def acquire(directory, exclusive=False, owner=None):
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if directory.is_symlink():
        raise OSError('The update coordination directory is invalid')
    if not exclusive and (directory/'.cutover.json').exists():
        raise BlockingIOError('A durable update barrier is active')
    parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        descriptor = os.open('.operations.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        if owner is not None:
            os.fchown(descriptor, *owner)
        fcntl.flock(descriptor, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        if not exclusive and (directory/'.cutover.json').exists():
            raise BlockingIOError('A durable update barrier is active')
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def set_barrier(directory, identity, owner=None):
    directory=Path(directory)
    if not isinstance(identity,str) or not identity or len(identity)>128:
        raise ValueError('Invalid barrier identity')
    temporary=directory/('.cutover-'+secrets.token_hex(8))
    descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(descriptor,'w') as output:
            json.dump({'id':identity},output);output.flush();os.fsync(output.fileno())
            if owner is not None:os.fchown(output.fileno(),*owner)
        temporary.replace(directory/'.cutover.json')
        parent=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(parent)
        finally:os.close(parent)
    finally:temporary.unlink(missing_ok=True)


def clear_barrier(directory, identity):
    path=Path(directory)/'.cutover.json'
    try:
        if path.is_symlink() or json.loads(path.read_text()).get('id')!=identity:return
        path.unlink()
        parent=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(parent)
        finally:os.close(parent)
    except FileNotFoundError:pass


@contextlib.contextmanager
def hold(directory, exclusive=False, owner=None):
    descriptor = acquire(directory, exclusive, owner)
    try:
        yield
    finally:
        os.close(descriptor)


class MutationMiddleware:
    def __init__(self, app, directory):
        self.app = app
        self.directory = directory

    async def __call__(self, scope, receive, send):
        path = scope.get('path', '')
        mutate = scope['type'] == 'http' and scope['method'] in {'POST', 'PUT', 'PATCH', 'DELETE'}
        if not mutate or path.startswith('/api/system/updates') or path == '/api/admin/token':
            return await self.app(scope, receive, send)
        try:
            descriptor = acquire(self.directory)
        except BlockingIOError:
            from starlette.responses import JSONResponse
            return await JSONResponse({'detail': 'Панель обновляется. Дождитесь завершения операции.'}, status_code=503)(scope, receive, send)
        try:
            return await self.app(scope, receive, send)
        finally:
            os.close(descriptor)
