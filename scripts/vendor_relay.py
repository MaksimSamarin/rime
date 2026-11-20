"""Fetch the checksum-qualified forwarding runtime during the image build."""
import hashlib
import io
from pathlib import Path
import tarfile
import urllib.request


VERSION = '3.3.3'
ARCHIVE_SHA256 = 'f4c1255dc892a7014c0ad6e5f1c3573108f7bea4403f04f21873406ab58aa666'
BINARY_SHA256 = 'a60f87707d679d154fad93d05313284baf3dea71fdb9ec18afecaac35db946dd'


def main():
    url = f'https://github.com/go-gost/gost/releases/download/v{VERSION}/gost_{VERSION}_linux_amd64.tar.gz'
    with urllib.request.urlopen(url, timeout=60) as response:
        raw = response.read(32 * 1024 * 1024 + 1)
    if len(raw) > 32 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != ARCHIVE_SHA256:
        raise ValueError('Forwarding runtime archive checksum differs')
    destination = Path('/opt/rime-relay')
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
        binary = archive.extractfile('gost').read()
        if hashlib.sha256(binary).hexdigest() != BINARY_SHA256:
            raise ValueError('Forwarding runtime binary checksum differs')
        (destination / 'gost').write_bytes(binary)
        (destination / 'gost').chmod(0o755)
        (destination / 'LICENSE.gost').write_bytes(archive.extractfile('LICENSE').read())


if __name__ == '__main__':
    main()
