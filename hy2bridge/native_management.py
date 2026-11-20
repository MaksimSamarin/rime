"""Read-only qualification of the selected authenticated native control path."""
import http.client
import json
import os
from pathlib import Path
import ssl
import tempfile

import rpyc

from xray_api import XRay


class ManagementNotReady(ValueError):
    pass


def cached_node(source):
    try:
        from app import xray
        return xray.nodes.get(source['native']['id'])
    except (ImportError, AttributeError, KeyError):
        return None


def controller_credentials():
    from app.xray.operations import get_tls
    return get_tls()


def ensure_management_sources(relays,source,profile,entry,services):
    if not any(service['kind']=='management' for service in services):return
    if (profile.get('vpn') or {}).get('management_auth')!='controller-mtls-v1' and not getattr(cached_node(source),'_api_mtls',False):
        raise ManagementNotReady('Обновите runtime ноды для защищённого управления через туннель')
    if (profile.get('vpn') or {}).get('management_source_policy')!=1 and not getattr(cached_node(source),'_management_sources',False):
        raise ManagementNotReady('Обновите runtime и наблюдатель ноды для доставки firewall через независимый канал')
    from .native_sources import current
    if current is None:
        raise ManagementNotReady('Канал доставки firewall ноды не настроен')
    node='xray:'+str(source['native']['id'])
    current.wait_applied(current.refresh(node,entry=entry))


def refresh_management_sources(relays,node):
    from .native_sources import current
    if current is not None and node.startswith('xray:'):
        try:current.refresh(node,clear_leases=True)
        except Exception:
            try:current.defer(node)
            except Exception:
                import logging
                logging.getLogger('rime').error('Native management source refresh requires retry for %s',node)


def protocol_for(source, profile, current):
    address = source['native']['address']
    try:
        options = json.loads(os.environ.get('RIME_NODE_CONTROL_OVERRIDES','{}'))
    except (TypeError,ValueError):
        options = {}
    explicit = options.get(address,{}) if isinstance(options,dict) else {}
    protocol = explicit.get('protocol') if isinstance(explicit,dict) else None
    if protocol in ('rest','rpyc'):
        return protocol
    name = type(current).__name__
    if name == 'ReSTXRayNode':
        return 'rest'
    if name == 'RPyCXRayNode':
        return 'rpyc'
    protocol = profile.get('vpn',{}).get('management_protocol')
    if protocol not in ('rest','rpyc'):
        raise ManagementNotReady('Протокол управления нодой не сохранён')
    return protocol


def read_rest(address, port, context):
    connection = http.client.HTTPSConnection(address,port,context=context,timeout=3)
    try:
        connection.request('POST','/',body=b'{}',headers={'Content-Type':'application/json'})
        response = connection.getresponse()
        raw = response.read(16385)
        if response.status != 200 or len(raw)>16384:
            raise ValueError('Invalid native control response')
        return json.loads(raw)
    finally:
        connection.close()


def read_rpyc(address, port, key_path, certificate_path, trust_path):
    stream = rpyc.SocketStream.ssl_connect(address,port,
        {'keyfile':str(key_path),'certfile':str(certificate_path),'ca_certs':str(trust_path),
         'cert_reqs':ssl.CERT_REQUIRED,'check_hostname':False},timeout=3)
    connection = None
    try:
        connection = rpyc.connect_stream(stream,config={'sync_request_timeout':3})
        raw = connection.root.capabilities()
        if not isinstance(raw,str) or len(raw)>16384:
            raise ValueError('Invalid native capability response')
        return json.loads(raw)
    finally:
        if connection is not None:
            connection.close()
        else:
            stream.close()


def probe_management(source, profile, entry, services, credentials_provider=None):
    selected = [service for service in services if service['kind']=='management']
    if not selected:
        return {'passed':True,'management_passed':None,'services':[]}
    stage = 'configuration'
    results = []
    try:
        native = source.get('native')
        if not native:
            raise ManagementNotReady('Выбранная нода не поддерживает native-управление')
        current = cached_node(source)
        vpn = profile.get('vpn',{})
        qualified = vpn.get('management_auth')=='controller-mtls-v1' or getattr(current,'_api_mtls',False) is True
        if not qualified:
            raise ManagementNotReady('Обновите runtime ноды для защищённого управления через туннель')
        protocol = protocol_for(source,profile,current)
        certificate = (vpn.get('management_tls',{}).get('certificate')
                       or vpn.get('management_server_certificate') or getattr(current,'_node_cert',None))
        if not isinstance(certificate,str) or not certificate:
            raise ManagementNotReady('Сертификат управления нодой не сохранён')
        from .native_trust import current as trust,match_certificate
        if trust is not None:
            certificate=trust.expected('xray:'+str(native['id']))
        elif getattr(current,'_trusted_server_certificate',None):
            certificate=match_certificate(current._trusted_server_certificate,certificate)
        control = [service for service in selected if service['origin_port']==native['port']]
        api = [service for service in selected if service['origin_port']==native['api_port']]
        if len(control)!=1 or len(api)!=1 or control[0]['id']==api[0]['id']:
            raise ManagementNotReady('Карта портов управления нодой требует сверки')
        credentials = (credentials_provider or controller_credentials)()
        if isinstance(credentials,tuple):
            key, client_certificate = credentials
        else:
            key, client_certificate = credentials['key'], credentials['certificate']
        if not isinstance(key,str) or not isinstance(client_certificate,str) or not key or not client_certificate:
            raise ManagementNotReady('Клиентский сертификат управления недоступен')
        with tempfile.TemporaryDirectory(prefix='rime-management-check-') as folder:
            root = Path(folder)
            key_path, certificate_path, trust_path = root/'client.key', root/'client.pem', root/'server.pem'
            for path,value in [(key_path,key),(certificate_path,client_certificate),(trust_path,certificate)]:
                path.write_text(value)
                path.chmod(0o600)
            context = ssl.create_default_context(cadata=certificate)
            context.check_hostname = False
            context.load_cert_chain(str(certificate_path),str(key_path))
            stage = 'control'
            status = read_rest(entry['address'],control[0]['public_port'],context) if protocol=='rest' else read_rpyc(
                entry['address'],control[0]['public_port'],key_path,certificate_path,trust_path)
            if not isinstance(status,dict) or status.get('api_mtls')!=1 or status.get('management_sources')!=1 or status.get('api_direct')!=1 or status.get('started') is not True:
                raise ManagementNotReady('Нода не подтвердила защищённый работающий API')
            results.append({'kind':'management','origin_port':control[0]['origin_port'],
                            'public_port':control[0]['public_port'],'passed':True,'stage':'control'})
            stage = 'api'
            connection = XRay(entry['address'],api[0]['public_port'],ssl_cert=certificate.encode(),
                ssl_target_name='Gozargah',ssl_key=key.encode(),client_cert=client_certificate.encode(),
                control_identity=(native['address'],native['api_port']))
            try:
                connection.get_sys_stats(timeout=3)
            finally:
                connection._channel.close()
            results.append({'kind':'management','origin_port':api[0]['origin_port'],
                            'public_port':api[0]['public_port'],'passed':True,'stage':'api'})
        return {'passed':True,'management_passed':True,'services':results}
    except Exception as error:
        completed = {row['origin_port'] for row in results}
        results.extend({'kind':'management','origin_port':service['origin_port'],
                        'public_port':service['public_port'],'passed':False,'stage':stage}
                       for service in selected if service['origin_port'] not in completed)
        return {'passed':False,'management_passed':None if stage=='configuration' else False,
                'stage':stage,'error':type(error).__name__,
                'message':str(error) if isinstance(error,ManagementNotReady) else 'Защищённое управление через вход не прошло проверку',
                'services':results}
