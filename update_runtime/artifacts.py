"""Portable Docker-save identity, independent of the daemon's image-store IDs."""
import hashlib
import gzip
import json
import re
import tarfile

from .releases import UpdateError


def archive_identity(path):
    try:
        with tarfile.open(path) as archive:
            metadata_file = archive.extractfile('manifest.json')
            if metadata_file is None:
                raise UpdateError('image_identity_mismatch')
            metadata = json.loads(metadata_file.read(65537))
            if not isinstance(metadata, list) or len(metadata) != 1:
                raise UpdateError('image_identity_mismatch')
            entry = metadata[0]
            name = entry['Config']
            if not re.fullmatch(r'(?:blobs/sha256/)?[a-f0-9]{64}(?:\.json)?', name):
                raise UpdateError('image_identity_mismatch')
            config_file = archive.extractfile(name)
            raw = config_file.read(2 * 1024 * 1024 + 1)
            if len(raw) > 2 * 1024 * 1024:
                raise UpdateError('image_identity_mismatch')
            config = json.loads(raw)
            return {'image_id': 'sha256:' + hashlib.sha256(raw).hexdigest(),
                    'tags': entry.get('RepoTags') or [], 'config': config}
    except (tarfile.TarError, KeyError, TypeError, ValueError, OSError, AttributeError):
        raise UpdateError('image_identity_mismatch') from None


def new_layer_bytes(path, existing, limit):
    """Bound decompression and count only layers absent from the current image."""
    total = 0
    try:
        with tarfile.open(path) as archive:
            metadata = json.load(archive.extractfile('manifest.json'))[0]
            config = json.load(archive.extractfile(metadata['Config']))
            layers = metadata['Layers']
            identities = config['rootfs']['diff_ids']
            if len(layers) != len(identities):
                raise UpdateError('image_identity_mismatch')
            for name, identity in zip(layers, identities):
                if identity in existing:
                    continue
                with archive.extractfile(name) as source:
                    compressed = source.read(2) == b'\x1f\x8b'
                    source.seek(0)
                    if compressed:
                        with gzip.GzipFile(fileobj=source) as layer:
                            while block := layer.read(1024 * 1024):
                                total += len(block)
                                if total > limit:
                                    raise UpdateError('insufficient_disk_space')
                    else:
                        total += archive.getmember(name).size
                    if total > limit:
                        raise UpdateError('insufficient_disk_space')
        return total
    except UpdateError:
        raise
    except (tarfile.TarError, KeyError, TypeError, ValueError, OSError, AttributeError, EOFError):
        raise UpdateError('image_identity_mismatch') from None
