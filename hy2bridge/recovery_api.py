"""Sudo-only import and direct SSH capture of node recovery configurations."""
import base64
import json
from pathlib import Path
from typing import Annotated

from fastapi import Depends,HTTPException,Request
from pydantic import BaseModel,Field,StrictInt

from .provision import ProvisionError
from .recovery import MAX_ARCHIVE_BYTES,MAX_PROFILE_BYTES


class CaptureRequest(BaseModel):
    host:str=Field(min_length=1,max_length=253)
    address:str=Field(min_length=1,max_length=45)
    ssh_port:Annotated[StrictInt,Field(ge=1,le=65535)]=22
    username:str=Field(min_length=1,max_length=64)
    password:str=Field(default='',max_length=1024)
    private_key:str=Field(default='',max_length=16384)
    key_passphrase:str=Field(default='',max_length=1024)
    fingerprint:str=Field(pattern=r'^SHA256:[A-Za-z0-9+/]{43}$')


def install(app,transfer):
    from app.models.admin import Admin
    recovery=transfer.recovery

    def source(node):
        with transfer.store.connection() as db:
            if db.execute("SELECT 1 FROM fleet_node_transfers WHERE node=? AND state='switched'",(node,)).fetchone():
                raise ProvisionError('Дождитесь завершения переноса перед обновлением комплекта')
            return transfer.snapshot(node,db)

    def call(function,*args):
        try:return function(*args)
        except ProvisionError as error:raise HTTPException(409,str(error)) from None

    @app.get('/api/fleet/nodes/{node}/recovery',tags=['Fleet'])
    def status(node:str,admin=Depends(Admin.check_sudo_admin)):
        call(source,node)
        return call(recovery.summary,node)

    @app.post('/api/fleet/nodes/{node}/recovery/import',tags=['Fleet'])
    async def import_archive(node:str,request:Request,admin=Depends(Admin.check_sudo_admin)):
        original=call(source,node)
        content=bytearray()
        async for part in request.stream():
            content.extend(part)
            if len(content)>MAX_ARCHIVE_BYTES:raise HTTPException(413,'Архив конфигурации больше 64 MiB')
        with transfer.lifecycle.guard:
            if transfer.digest(call(source,node))!=transfer.digest(original):raise HTTPException(409,'Нода изменилась во время загрузки')
            return call(recovery.import_archive,node,bytes(content),original['domain'])

    @app.post('/api/fleet/nodes/{node}/recovery/capture',tags=['Fleet'])
    def capture(node:str,request:CaptureRequest,admin=Depends(Admin.check_sudo_admin)):
        data=request.model_dump()
        original=call(source,node)
        try:
            expected=transfer.resolve(original['identity']['address'],data['ssh_port'])
            if data['address'] not in expected:raise ProvisionError('SSH-адрес отличается от текущего адреса исходной ноды')
            with transfer.store.connection() as db:
                vpn=[row['id'] for row in db.execute("SELECT id FROM fleet_node_transfers WHERE node=? AND state='succeeded' ORDER BY created_at DESC LIMIT 1",(node,))]
                if original['managed']:vpn.append(original['managed']['id'])
            proxies=[row.get('runtime_id') or row['id'] for row in original.get('proxies',[])]
            code=base64.b64encode(Path(__file__).with_name('recovery_export.py').read_bytes()).decode()
            with transfer.connect(data) as client:
                incoming,output,errors=client.exec_command('python3 -c "import base64;exec(base64.b64decode(\''+code+'\'))"',timeout=120)
                incoming.write(json.dumps({'vpn_ids':list(dict.fromkeys(vpn)),'proxy_ids':proxies}))
                incoming.flush();incoming.channel.shutdown_write()
                raw=output.read(MAX_PROFILE_BYTES+1)
                if output.channel.recv_exit_status()!=0 or len(raw)>MAX_PROFILE_BYTES:raise ProvisionError('Не удалось прочитать конфигурацию исходной ноды')
            value=json.loads(raw)
            with transfer.lifecycle.guard:
                if transfer.digest(source(node))!=transfer.digest(original):raise ProvisionError('Нода изменилась во время чтения конфигурации')
                return recovery.import_files(node,value['files'],original['domain'])
        except ProvisionError as error:raise HTTPException(409,str(error)) from None
        finally:data.clear()
