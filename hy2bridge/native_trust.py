"""Persist the administrator/SSH-verified identity of each physical native node."""
import hashlib
import hmac
import ssl
import time
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding


current = None


class NodeCertificateError(ConnectionError):
    pass


def certificate_der(value):
    if not isinstance(value,str) or len(value)>131072:
        raise NodeCertificateError('Некорректный сертификат управления нодой')
    try:
        return x509.load_pem_x509_certificate(value.encode()).public_bytes(Encoding.DER)
    except (ValueError,ssl.SSLError):
        raise NodeCertificateError('Некорректный сертификат управления нодой') from None


def canonical_certificate(value):
    # A PEM chain is not a pin: additional roots would broaden the trust used
    # by the second (configuration/gRPC) connection after the identity probe.
    return x509.load_der_x509_certificate(certificate_der(value)).public_bytes(Encoding.PEM).decode()


def match_certificate(expected, observed):
    if not expected:
        raise NodeCertificateError('Сертификат управления нодой не закреплён. Подтвердите сертификат при регистрации или импортируйте проверенный комплект')
    if not hmac.compare_digest(hashlib.sha256(certificate_der(expected)).digest(),
                               hashlib.sha256(certificate_der(observed)).digest()):
        raise NodeCertificateError('Сертификат управления нодой изменился. Подключение отклонено; проверьте сервер перед повторной регистрацией')
    return canonical_certificate(expected)


class NativeTrust:
    def __init__(self,store,recovery):
        self.store,self.recovery=store,recovery
        with store.connection(write=True) as db:
            db.execute('''CREATE TABLE IF NOT EXISTS fleet_native_trust(
                node TEXT PRIMARY KEY,generation TEXT NOT NULL,certificate TEXT NOT NULL,verified_at REAL NOT NULL)''')

    @staticmethod
    def generation(db,node):
        if not node.startswith('xray:') or not node[5:].isdigit():
            raise NodeCertificateError('Неверная идентичность native-ноды')
        row=db.execute('SELECT created_at FROM nodes WHERE id=?',(int(node[5:]),)).fetchone()
        if not row:raise NodeCertificateError('Native-нода отсутствует')
        return str(row['created_at'])

    def enroll(self,node,certificate):
        """Accept only an explicit administrator or pinned-SSH registration value."""
        certificate=canonical_certificate(certificate)
        with self.store.connection(write=True) as db:
            generation=self.generation(db,node)
            old=db.execute('SELECT * FROM fleet_native_trust WHERE node=?',(node,)).fetchone()
            if old and old['generation']==generation:
                match_certificate(old['certificate'],certificate)
                return canonical_certificate(old['certificate'])
            db.execute('INSERT OR REPLACE INTO fleet_native_trust VALUES(?,?,?,?)',
                       (node,generation,certificate,time.time()))
        return certificate

    @staticmethod
    def snapshot(db,node):
        row=db.execute('SELECT * FROM fleet_native_trust WHERE node=?',(node,)).fetchone()
        return dict(row) if row else None

    @staticmethod
    def enroll_verified_transfer(db,node,certificate,expected):
        """CAS a certificate returned by the destination's pinned SSH worker."""
        certificate=canonical_certificate(certificate)
        previous=NativeTrust.snapshot(db,node)
        if previous!=expected:raise NodeCertificateError('Сертификат ноды изменился во время подготовки переноса')
        generation=NativeTrust.generation(db,node)
        if previous and previous['generation']==generation:
            try:
                match_certificate(previous['certificate'],certificate)
                return previous
            except NodeCertificateError:pass
        db.execute('INSERT OR REPLACE INTO fleet_native_trust VALUES(?,?,?,?)',
                   (node,generation,certificate,time.time()))
        return NativeTrust.snapshot(db,node)

    @staticmethod
    def restore_transfer(db,node,expected,previous):
        if NativeTrust.snapshot(db,node)!=expected:
            raise NodeCertificateError('Сертификат ноды изменился. Автоматический откат остановлен')
        db.execute('DELETE FROM fleet_native_trust WHERE node=?',(node,))
        if previous:
            columns=('node','generation','certificate','verified_at')
            db.execute('INSERT INTO fleet_native_trust VALUES(?,?,?,?)',tuple(previous[key] for key in columns))

    def expected(self,node):
        with self.store.connection() as db:
            generation=self.generation(db,node)
            row=db.execute('SELECT * FROM fleet_native_trust WHERE node=?',(node,)).fetchone()
            if row and row['generation']==generation:return canonical_certificate(row['certificate'])
        profile=self.recovery.load(node)
        vpn=profile.get('vpn') or {}
        certificate=(vpn.get('management_tls') or {}).get('certificate')
        if not certificate and vpn.get('management_certificate_verified') is True:
            certificate=vpn.get('management_server_certificate')
        if certificate:return self.enroll(node,certificate)
        self.event(node,'native_tls_unverified')
        raise NodeCertificateError('Сертификат управления нодой не закреплён. Импортируйте проверенный комплект или подтвердите сертификат при регистрации')

    def verify(self,node,expected,observed):
        try:
            match_certificate(self.expected(node),expected)
            result=match_certificate(expected,observed)
        except NodeCertificateError:
            self.event(node,'native_tls_identity_changed')
            raise
        with self.store.connection(write=True) as db:
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='fleet_events'").fetchone():
                db.execute("UPDATE fleet_events SET resolved_at=?,last_at=? WHERE node=? AND resolved_at IS NULL AND code IN ('native_tls_identity_changed','native_tls_unverified')",(time.time(),time.time(),node))
        return result

    def event(self,node,code):
        with self.store.connection(write=True) as db:
            if not db.execute("SELECT 1 FROM sqlite_master WHERE name='fleet_events'").fetchone():return
            now=time.time()
            row=db.execute('SELECT id FROM fleet_events WHERE node=? AND code=? AND resolved_at IS NULL',(node,code)).fetchone()
            if row:db.execute('UPDATE fleet_events SET last_at=?,occurrences=occurrences+1 WHERE id=?',(now,row['id']))
            else:db.execute('INSERT INTO fleet_events(node,code,severity,first_at,last_at) VALUES(?,?,?,?,?)',(node,code,'error',now,now))


def client_options(dbnode):
    if current is None:
        raise NodeCertificateError('Хранилище доверенных сертификатов нод ещё не готово')
    node='xray:'+str(dbnode.id)
    expected=current.expected(node)
    return {'server_certificate':expected,
            'certificate_verifier':lambda observed:current.verify(node,expected,observed)}
