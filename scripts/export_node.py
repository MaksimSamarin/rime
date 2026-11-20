"""Export one qualified native runtime for both wizard image settings."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from update_runtime.artifacts import archive_identity
from update_runtime.releases import REPOSITORY, version_key
from vendor_xray import VERSION, BINARY_SHA256


def command(arguments):
    return subprocess.check_output(arguments, text=True).strip()


def write_metadata(path, value):
    with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent,
                                     prefix='.'+path.name+'-', delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(value)
    try:
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', required=True, help='Local image built with --target node-source')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.image.startswith('-'):
        raise SystemExit('Provide a local native image reference.')
    info = json.loads(command(['docker', 'image', 'inspect', args.image]))[0]
    labels = info.get('Config', {}).get('Labels') or {}
    expected = {'org.opencontainers.image.source':'https://github.com/'+REPOSITORY,
                'org.rime.runtime.kind':'node','org.rime.xray.version':VERSION,
                'org.rime.management.auth':'controller-mtls-v1'}
    if any(labels.get(key) != value for key,value in expected.items()):
        raise SystemExit('The image must be the qualified Rime native runtime.')
    version = labels.get('org.opencontainers.image.version','')
    version_key(version)
    if info.get('Os') != 'linux' or info.get('Architecture') != 'amd64':
        raise SystemExit('The native export is qualified for Linux amd64.')
    # Inspect the immutable selected image before exporting it. This process
    # reads files and the version only and starts no VPN or controller service.
    verification = '''
from pathlib import Path
import hashlib,json,subprocess
import sys
sys.path.insert(0,'/code')
import xray,node_autonomy
assert xray.RIME_API_MTLS is True
assert node_autonomy.capabilities(None)['api_mtls']==1
assert node_autonomy.capabilities(None)['management_sources']==1
assert node_autonomy.capabilities(None)['api_direct']==1
assert callable(node_autonomy.core_epoch)
assert 'stats_epoch' in node_autonomy.capabilities(None)
binary=Path('/usr/local/bin/xray')
source=Path('/code/rest_service.py').read_text()
assert source.count('from node_autonomy import ')==1
assert Path('/code/node_autonomy.py').is_file()
assert Path('/code/api_bridge.py').is_file()
assert 'from api_bridge import internal_endpoint' in Path('/code/xray.py').read_text()
assert 'def capabilities' in Path('/code/rpyc_service.py').read_text()
assert Path('/opt/rime-xray/LICENSE.xray').stat().st_size>0
print(json.dumps({'version':subprocess.check_output([str(binary),'version'],text=True).splitlines()[0],
    'sha256':hashlib.sha256(binary.read_bytes()).hexdigest()}))
'''
    runtime = json.loads(command(['docker','run','--rm','--network','none','--read-only',
        '--cap-drop','ALL','--security-opt','no-new-privileges','--entrypoint','python',
        info['Id'],'-c',verification]))
    if runtime['sha256'] != BINARY_SHA256 or not runtime['version'].startswith('Xray '+VERSION+' '):
        raise SystemExit('The native image contains a different Xray runtime.')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    name = 'rime-node-'+version+'-xray-'+VERSION+'-linux-amd64.tar.gz'
    archive_path = output/name
    if archive_path.is_symlink():
        raise SystemExit('The native archive destination must be a regular file.')
    with tempfile.NamedTemporaryFile(dir=output,prefix='.node-export-',suffix='.tar.gz',delete=False) as stream:
        temporary = Path(stream.name)
    process = None
    try:
        # Export by immutable ID so a concurrently retagged name cannot change
        # the already verified content. Every invocation creates a fresh file.
        process = subprocess.Popen(['docker','image','save',info['Id']],stdout=subprocess.PIPE)
        with temporary.open('wb') as raw:
            with gzip.GzipFile(filename='',fileobj=raw,mode='wb',compresslevel=1,mtime=0) as destination:
                shutil.copyfileobj(process.stdout,destination)
            raw.flush()
            os.fsync(raw.fileno())
        process.stdout.close()
        if process.wait() != 0:
            raise RuntimeError('Native image export failed.')
        identity = archive_identity(temporary)
        config = identity['config']
        if (config.get('os') != 'linux' or config.get('architecture') != 'amd64'
                or config.get('rootfs',{}).get('diff_ids') != info.get('RootFS',{}).get('Layers')
                or config.get('config') != info.get('Config')):
            raise RuntimeError('The saved image differs from the verified native image.')
        checksum = hashlib.sha256()
        with temporary.open('rb') as stream:
            for block in iter(lambda:stream.read(1024 * 1024),b''):
                checksum.update(block)
        digest = checksum.hexdigest()
        portable_id = identity['image_id']
        manifest = {'schema':1,'repository':REPOSITORY,'version':version,
                    'revision':labels.get('org.opencontainers.image.revision'),
                    'xray_version':VERSION,'xray_binary_sha256':BINARY_SHA256,
                    'management_auth':'controller-mtls-v1',
                    'management_sources':1,
                    'api_direct':1,
                    'image_id':portable_id,'python_image':portable_id,
                    'vless_template_image':portable_id,'base_image_bundle':name,
                    'base_image_bundle_sha256':digest,'base_image_bundle_bytes':temporary.stat().st_size}
        temporary.replace(archive_path)
        write_metadata(output/'rime-node-runtime.json',json.dumps(manifest,indent=2)+'\n')
        write_metadata(output/'rime-node-SHA256SUMS',digest+'  '+name+'\n')
        print(json.dumps(manifest,indent=2))
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            process.wait()
        if process is not None and process.stdout is not None:
            process.stdout.close()
        temporary.unlink(missing_ok=True)


if __name__ == '__main__':
    main()
