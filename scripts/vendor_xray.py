"""Fetch the qualified Linux amd64 Xray runtime during an image build."""
import argparse
import hashlib
import io
from pathlib import Path
import tempfile
import urllib.request
import zipfile


VERSION = '26.6.1'
ARCHIVE_SHA256 = '136e822e99e616692550723e8b607cd8858c62a390aea5704938bc27930904ba'
BINARY_SHA256 = '402c34d5d537a48c858d6d227c1e660eda8bf8abe9d1258d54faa66b8b263b78'
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_BINARY_BYTES = 64 * 1024 * 1024


def replace_file(path, content, mode):
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.'+path.name+'-', delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(content)
    try:
        temporary.chmod(mode)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def install(directory, archive_path=None):
    if archive_path is None:
        url = f'https://github.com/XTLS/Xray-core/releases/download/v{VERSION}/Xray-linux-64.zip'
        with urllib.request.urlopen(url, timeout=90) as response:
            raw = response.read(MAX_ARCHIVE_BYTES + 1)
    else:
        if archive_path.stat().st_size > MAX_ARCHIVE_BYTES:
            raise ValueError('Xray archive exceeds the qualified size limit')
        raw = archive_path.read_bytes()
    if len(raw) > MAX_ARCHIVE_BYTES or hashlib.sha256(raw).hexdigest() != ARCHIVE_SHA256:
        raise ValueError('Xray archive checksum differs')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        names = archive.namelist()
        if names.count('xray') != 1 or names.count('LICENSE') != 1:
            raise ValueError('Xray executable or license is missing or duplicated')
        if archive.getinfo('xray').file_size > MAX_BINARY_BYTES or archive.getinfo('LICENSE').file_size > 1024 * 1024:
            raise ValueError('Xray release member exceeds the qualified size limit')
        binary = archive.read('xray')
        license_text = archive.read('LICENSE')
    if hashlib.sha256(binary).hexdigest() != BINARY_SHA256 or not license_text.strip():
        raise ValueError('Xray executable checksum or license differs')
    directory.mkdir(parents=True, exist_ok=True)
    replace_file(directory/'xray', binary, 0o755)
    replace_file(directory/'LICENSE.xray', license_text, 0o644)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--directory', type=Path, default=Path('/opt/rime-xray'))
    parser.add_argument('--archive', type=Path, help='Use a local archive with the same required checksum')
    args = parser.parse_args()
    install(args.directory, args.archive)
    print('Qualified Xray '+VERSION+' and its license are ready.')


if __name__ == '__main__':
    main()
