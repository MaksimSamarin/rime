"""Authenticated TLS control of one entry server's forwarding services."""
import base64
import hashlib
import http.client
import json
import socket
import ssl
import urllib.parse
from datetime import datetime, timedelta, timezone
import ipaddress
import secrets

from .provision import ProvisionError


class RelayPortConflict(ProvisionError):
    service = None


def credentials(host, address):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Rime entry control')])
    names = [x509.IPAddress(ipaddress.ip_address(address))]
    try:
        ipaddress.ip_address(host)
    except ValueError:
        names.append(x509.DNSName(host))
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5))
        .not_valid_after(now+timedelta(days=730)).add_extension(x509.SubjectAlternativeName(names),critical=False)
        .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),critical=False)
        .sign(key,hashes.SHA256()))
    return {'certificate':certificate.public_bytes(serialization.Encoding.PEM).decode(),
            'key':key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()).decode(),
            'username':'rime_control','password':secrets.token_urlsafe(32),'meter_token':secrets.token_urlsafe(40),
            'observer_token':secrets.token_urlsafe(40)}


def initial_configuration(credential, control_port, metrics_port, directory, api_port):
    return {'services':[{'name':'rime-control','addr':'0.0.0.0:'+str(control_port),
            'handler':{'type':'tcp'},
            'listener':{'type':'tls','tls':{'certFile':directory+'/control-cert.pem','keyFile':directory+'/control-key.pem'}},
            'forwarder':{'nodes':[{'name':'control-api','addr':'127.0.0.1:'+str(api_port)}]}}],
            'api':{'addr':'127.0.0.1:'+str(api_port),'pathPrefix':'/api',
                   'auth':{'username':credential['username'],'password':credential['password']}},
            'observers':[{'name':'rime-meter','plugin':{'type':'http',
                'addr':'http://127.0.0.1:'+str(metrics_port)+'/observe','timeout':'2s',
                'token':credential['observer_token']}}],
            'log':{'level':'warn'}}


class RelayControl:
    def __init__(self, host, address, port, credential):
        self.host = host
        self.address = address
        self.port = port
        self.timeout = 12
        self.context = ssl.create_default_context(cadata=credential['certificate'])
        value = credential['username'] + ':' + credential['password']
        self.authorization = 'Basic ' + base64.b64encode(value.encode()).decode()

    def request(self, method, path, value=None, missing_ok=False):
        connection = http.client.HTTPSConnection(self.host, self.port, context=self.context, timeout=self.timeout)
        connection._create_connection = lambda address, timeout=None, source_address=None: socket.create_connection((self.address, self.port), timeout)
        headers = {'Authorization': self.authorization}
        body = None
        if value is not None:
            body = json.dumps(value).encode()
            headers['Content-Type'] = 'application/json'
        try:
            connection.request(method, '/api/config' + path, body, headers)
            response = connection.getresponse()
            raw = response.read(1024 * 1024 + 1)
            if response.status == 404 and missing_ok:
                return None
            if response.status>=300 and b'bind' in raw and b'address already in use' in raw:
                raise RelayPortConflict('Порт входного сервера уже занят')
            if response.status >= 300 or len(raw) > 1024 * 1024:
                raise ProvisionError('Входной сервер не подтвердил изменение туннеля')
            result = json.loads(raw) if raw else {}
            if result.get('code', 0) not in (0, 200):
                raise ProvisionError('Входной сервер отклонил конфигурацию туннеля')
            return result
        except ProvisionError:
            raise
        except (OSError, ValueError):
            raise ProvisionError('Защищённый API входного сервера недоступен') from None
        finally:
            connection.close()

    def add(self, service):
        try:return self.request('POST', '/services', service)
        except RelayPortConflict as error:
            error.service=service['name']
            raise

    def remove(self, name):
        return self.request('DELETE', '/services/' + urllib.parse.quote(name, safe=''), missing_ok=True)

    def save(self):
        return self.request('POST', '?format=json')

    def services(self):
        value = self.request('GET', '/services')
        data = value.get('data', value)
        return data.get('list', data.get('services', [])) if isinstance(data, dict) else data


def forwarding_service(identity, listen_port, target, target_port, protocol):
    if protocol not in {'tcp', 'udp'}:
        raise ProvisionError('Протокол перенаправления не поддерживается')
    listener = {'type': protocol}
    if protocol == 'udp':
        # GOST's JSON API decodes numbers as float64, while GetInt accepts
        # integer strings. Keep these explicit across hot updates and restarts.
        listener['metadata'] = {'keepAlive': True, 'ttl': '120s', 'readBufferSize': '65535'}
    handler = {'type':protocol}
    if protocol == 'udp':
        handler['metadata'] = {'bufferSize':'65535'}
    return {'name': 'rime-' + identity, 'addr': '0.0.0.0:' + str(listen_port),
            'handler': handler, 'listener': listener, 'observer':'rime-meter',
            'metadata':{'enableStats':True,'observer.period':'1s','observer.resetTraffic':False},
            'forwarder': {'nodes': [{'name': 'origin', 'addr': target + ':' + str(target_port)}]}}


def allocate_ports(services, occupied):
    used = set(occupied)
    result = []
    for service in services:
        selected = service['origin_port']
        if (selected, service['protocol']) in used or selected in {22}:
            selected = next((port for port in range(10443, 65536) if (port, service['protocol']) not in used), None)
        if selected is None:
            raise ProvisionError('На входном сервере не осталось свободных портов')
        used.add((selected, service['protocol']))
        result.append({**service, 'public_port': selected})
    return result


def configuration_digest(services):
    return hashlib.sha256(json.dumps(services, sort_keys=True).encode()).hexdigest()


def canonical_service(value):
    """Compare owned GOST settings while ignoring only runtime status/key case."""
    def normalized(item):
        if isinstance(item,list):return [normalized(value) for value in item]
        if not isinstance(item,dict):return item
        result={}
        for key,setting in item.items():
            if key=='metadata' and isinstance(setting,dict):
                metadata={}
                for name,value in setting.items():
                    canonical=name.lower()
                    if canonical in metadata:
                        raise ProvisionError('Метаданные правила содержат неоднозначные имена')
                    metadata[canonical]=value
                result[key]=metadata
            else:result[key]=normalized(setting)
        return result
    if isinstance(value,dict):value={key:item for key,item in value.items() if key!='status'}
    return normalized(value)


def certificate_covers(pem, domain):
    from cryptography import x509
    certificate=x509.load_pem_x509_certificate(pem.encode())
    san=certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    names=san.get_values_for_type(x509.DNSName)+[str(value) for value in san.get_values_for_type(x509.IPAddress)]
    domain=domain.lower()
    return any(domain==name.lower() or (name.startswith('*.') and domain.count('.')==name.count('.') and domain.endswith(name[1:].lower())) for name in names)
