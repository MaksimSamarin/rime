"""Export a verified Docker image and the manifest consumed by the panel updater."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import os

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from update_runtime.artifacts import archive_identity
from update_runtime.releases import REPOSITORY, version_key


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--version', required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--signing-key',default=os.environ.get('RIME_RELEASE_SIGNING_KEY_FILE'))
    args = parser.parse_args()
    if not args.signing_key:raise SystemExit('An offline Ed25519 release signing key is required.')
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from update_runtime.signatures import sign_manifest,verify_signature
    signing_key=load_pem_private_key(Path(args.signing_key).read_bytes(),password=None)
    if not isinstance(signing_key,Ed25519PrivateKey):raise SystemExit('Use an Ed25519 signing key.')
    verify_signature(b'Rime release signing key check',sign_manifest(b'Rime release signing key check',signing_key))
    version_key(args.version)
    if not re.fullmatch(r'[a-f0-9]{40}', args.revision):
        raise SystemExit('Provide the full source revision.')
    image = 'rime:' + args.version
    info = json.loads(subprocess.check_output(['docker', 'image', 'inspect', image]))[0]
    labels = info.get('Config', {}).get('Labels') or {}
    expected = {'org.opencontainers.image.source': 'https://github.com/' + REPOSITORY,
                'org.opencontainers.image.version': args.version,
                'org.opencontainers.image.revision': args.revision}
    if any(labels.get(key) != value for key, value in expected.items()):
        raise SystemExit('Image source, version or revision does not match the release.')
    if info['Os'] != 'linux' or info['Architecture'] != 'amd64':
        raise SystemExit('This release recipe is qualified for Linux amd64.')
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    archive = output / 'rime-linux-amd64.tar.gz'
    process = subprocess.Popen(['docker', 'image', 'save', image], stdout=subprocess.PIPE)
    with gzip.open(archive, 'wb', compresslevel=1) as destination:
        shutil.copyfileobj(process.stdout, destination)
    process.stdout.close()
    if process.wait() != 0:
        raise SystemExit('Docker image export failed.')
    identity = archive_identity(archive)
    if identity['tags'] != [image]:
        raise SystemExit('The export contains an unexpected image reference.')
    with archive.open('rb') as source:
        digest = hashlib.file_digest(source, 'sha256').hexdigest()
    manifest = {'schema': 1, 'repository': REPOSITORY, 'version': args.version, 'revision': args.revision,
                'artifacts': {'linux/amd64': {'name': archive.name, 'sha256': digest,
                                            'size': archive.stat().st_size, 'image_id': identity['image_id']}}}
    native=output/'rime-node-runtime.json'
    if native.exists():
        native_manifest=json.loads(native.read_text())
        manifest['native_runtime']={'manifest':native.name,'sha256':hashlib.sha256(native.read_bytes()).hexdigest(),
                                  'bundle':native_manifest['base_image_bundle'],
                                  'bundle_sha256':native_manifest['base_image_bundle_sha256']}
    raw=(json.dumps(manifest,indent=2)+'\n').encode()
    (output / 'rime-release.json').write_bytes(raw)
    (output / 'rime-release.sig').write_text(json.dumps(sign_manifest(raw,signing_key),indent=2)+'\n')
    (output / 'SHA256SUMS').write_text(digest + '  ' + archive.name + '\n')
    print('Release archive and manifest are ready.')


if __name__ == '__main__':
    main()
