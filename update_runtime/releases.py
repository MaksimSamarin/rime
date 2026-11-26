"""Read published Rime release metadata without sending installation details."""
import hashlib
import json
import platform
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

REPOSITORY = 'MaksimSamarin/rime'
API_ROOT = 'https://api.github.com'
VERSION_PATTERN = re.compile(r'^v?(\d+)\.(\d+)\.(\d+)(?:-rc\.?(\d+))?$')
DIGEST_PATTERN = re.compile(r'^[a-f0-9]{64}$')


class UpdateError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def version_key(value):
    if not isinstance(value, str) or len(value) > 64:
        raise UpdateError('invalid_version')
    match = VERSION_PATTERN.fullmatch(value)
    if not match:
        raise UpdateError('invalid_version')
    major, minor, patch, candidate = match.groups()
    return int(major), int(minor), int(patch), candidate is None, int(candidate or 0)


def architecture():
    names = {'x86_64': 'amd64', 'amd64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}
    try:
        return names[platform.machine().lower()]
    except KeyError:
        raise UpdateError('unsupported_architecture') from None


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, validate):
        self.validate = validate

    def redirect_request(self, request, file, code, message, headers, url):
        self.validate(url)
        return super().redirect_request(request, file, code, message, headers, url)


class ReleaseCatalog:
    def __init__(self, api_root=API_ROOT, allow_local=False, public_keys=None):
        self.api_root = api_root.rstrip('/')
        parsed = urllib.parse.urlsplit(self.api_root)
        self.local_origin = self.api_root if allow_local and parsed.hostname == '127.0.0.1' else None
        if self.api_root != API_ROOT and not self.local_origin:
            raise UpdateError('invalid_release_source')
        if public_keys is not None and not self.local_origin:
            raise UpdateError('invalid_release_source')
        self.public_keys=public_keys
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
            SafeRedirect(self.validate_url),
        )

    def validate_url(self, url):
        parsed = urllib.parse.urlsplit(url)
        if parsed.username or parsed.password or parsed.fragment:
            raise UpdateError('invalid_release_source')
        origin = parsed.scheme + '://' + parsed.netloc
        if self.local_origin and origin == self.local_origin:
            return
        allowed = {'api.github.com', 'github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com'}
        if parsed.scheme != 'https' or parsed.hostname not in allowed or parsed.port not in (None, 443):
            raise UpdateError('invalid_release_source')

    def open(self, url, headers=None):
        self.validate_url(url)
        request = urllib.request.Request(url, headers={
            'Accept': 'application/vnd.github+json',
            'User-Agent': 'Rime-Updater',
            **(headers or {}),
        })
        try:
            return self.opener.open(request, timeout=15)
        except (OSError, urllib.error.URLError):
            raise UpdateError('release_unavailable') from None

    def read_json(self, url, limit=2 * 1024 * 1024):
        with self.open(url) as response:
            raw = response.read(limit + 1)
        if len(raw) > limit:
            raise UpdateError('invalid_release_manifest')
        try:
            return json.loads(raw), raw
        except (ValueError, UnicodeError):
            raise UpdateError('invalid_release_manifest') from None

    def release(self, metadata, machine=None):
        tag = metadata.get('tag_name', '')
        version_key(tag)
        assets = {asset['name']: asset for asset in metadata.get('assets', [])}
        if 'rime-release.json' not in assets or 'rime-release.sig' not in assets:
            raise UpdateError('release_not_ready')
        manifest_asset = assets['rime-release.json']
        manifest, raw = self.read_json(manifest_asset['browser_download_url'], 65536)
        signature,_=self.read_json(assets['rime-release.sig']['browser_download_url'],4096)
        from .signatures import verify_signature
        verify_signature(raw,signature,self.public_keys)
        version = tag.removeprefix('v')
        if manifest.get('schema') != 1 or manifest.get('repository') != REPOSITORY or manifest.get('version') != version:
            raise UpdateError('invalid_release_manifest')
        if not re.fullmatch(r'[a-f0-9]{40}', manifest.get('revision', '')):
            raise UpdateError('invalid_release_manifest')
        digest = manifest_asset.get('digest')
        if digest and digest != 'sha256:' + hashlib.sha256(raw).hexdigest():
            raise UpdateError('release_checksum_mismatch')
        machine = machine or architecture()
        artifact = manifest.get('artifacts', {}).get('linux/' + machine)
        if not isinstance(artifact, dict):
            raise UpdateError('unsupported_architecture')
        name = 'rime-linux-' + machine + '.tar.gz'
        if artifact.get('name') != name or name not in assets:
            raise UpdateError('release_not_ready')
        if not DIGEST_PATTERN.fullmatch(artifact.get('sha256', '')):
            raise UpdateError('invalid_release_manifest')
        if not re.fullmatch(r'sha256:[a-f0-9]{64}', artifact.get('image_id', '')):
            raise UpdateError('invalid_release_manifest')
        size = artifact.get('size')
        if type(size) is not int or not 0 < size <= 2 * 1024**3 or assets[name].get('size') != size:
            raise UpdateError('invalid_release_manifest')
        url = assets[name]['browser_download_url']
        self.validate_url(url)
        return {
            'id': str(metadata['id']), 'tag': tag, 'version': version,
            'notes': str(metadata.get('body') or '')[:20000],
            'published_at': metadata.get('published_at'),
            'manifest_sha256': hashlib.sha256(raw).hexdigest(),
            'revision': manifest['revision'], 'artifact': {**artifact, 'url': url},
        }

    def latest(self):
        items, _ = self.read_json(self.api_root + '/repos/' + REPOSITORY + '/releases?per_page=100')
        if not isinstance(items, list):
            raise UpdateError('invalid_release_manifest')
        ready = []
        for item in items:
            if item.get('draft') or item.get('prerelease') or not VERSION_PATTERN.fullmatch(item.get('tag_name', '')):
                continue
            if {'rime-release.json','rime-release.sig'}<={asset.get('name') for asset in item.get('assets', [])}:
                ready.append(item)
        if not ready:
            return None
        return self.release(max(ready, key=lambda item: version_key(item['tag_name'])))

    def by_tag(self, tag):
        version_key(tag)
        metadata, _ = self.read_json(self.api_root + '/repos/' + REPOSITORY + '/releases/tags/' + urllib.parse.quote(tag, safe=''))
        if metadata.get('draft') or metadata.get('prerelease'):
            raise UpdateError('release_not_ready')
        return self.release(metadata)
