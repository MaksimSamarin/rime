"""Authenticated proxy-password storage using a persistent private volume key."""
import base64
import os
from pathlib import Path
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class ProxySecretError(ValueError):
    pass


class ProxySecrets:
    def __init__(self, path):
        self.path = Path(path)

    def key(self, create=False):
        if not self.path.exists() and create:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_name('.proxy-key-' + secrets.token_hex(16))
            try:
                descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, 'wb') as stream:
                    stream.write(os.urandom(32))
                    stream.flush()
                    os.fsync(stream.fileno())
                try:
                    os.link(temporary, self.path)
                except FileExistsError:
                    pass
                if os.name != 'nt':
                    directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        os.fsync(directory)
                    finally:
                        os.close(directory)
            finally:
                temporary.unlink(missing_ok=True)
        try:
            if self.path.is_symlink() or not self.path.is_file():
                raise ProxySecretError('Ключ хранилища прокси недоступен. Восстановите его из резервной копии')
            if os.name != 'nt' and self.path.stat().st_mode & 0o077:
                raise ProxySecretError('Ключ хранилища прокси должен иметь права 0600')
            value = self.path.read_bytes()
            if len(value) != 32:
                raise ProxySecretError('Ключ хранилища прокси повреждён. Восстановите его из резервной копии')
            return value
        except OSError:
            raise ProxySecretError('Ключ хранилища прокси недоступен. Восстановите его из резервной копии') from None

    def encrypt(self, identity, password, create=False):
        nonce = os.urandom(12)
        value = AESGCM(self.key(create=create)).encrypt(nonce, password.encode('utf-8'), identity.encode('utf-8'))
        return 'v1:' + base64.b64encode(nonce + value).decode('ascii')

    def decrypt(self, identity, envelope):
        try:
            if not envelope.startswith('v1:'):
                raise ValueError()
            value = base64.b64decode(envelope[3:], validate=True)
            if len(value) < 29:
                raise ValueError()
            return AESGCM(self.key()).decrypt(value[:12], value[12:], identity.encode('utf-8')).decode('utf-8')
        except ProxySecretError:
            raise
        except (ValueError, InvalidTag, UnicodeError):
            raise ProxySecretError('Сохранённый пароль прокси не расшифрован. Проверьте ключ резервной копии') from None
