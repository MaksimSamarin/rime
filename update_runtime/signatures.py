"""Verify release manifests against a separately provisioned Ed25519 root."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from .releases import UpdateError

# Only public verification material belongs in the application and host worker.
TRUSTED_RELEASE_KEYS = {'c93e7e2e4288e936': 'WlR3Q4kWwbAT+YDab1MVYRY+g3pAK6YStYauaoC9MtI='}


def key_id(public):
    return hashlib.sha256(public).hexdigest()[:16]


def sign_manifest(raw, private):
    from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
    public=private.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    return {'schema':1,'algorithm':'Ed25519','key_id':key_id(public),
            'signature':base64.b64encode(private.sign(raw)).decode()}


def verify_signature(raw, envelope, public_keys=None):
    keys=TRUSTED_RELEASE_KEYS if public_keys is None else public_keys
    try:
        if (not isinstance(envelope,dict) or envelope.get('schema')!=1
                or envelope.get('algorithm')!='Ed25519' or envelope.get('key_id') not in keys):
            raise ValueError('Unknown signing key')
        public=base64.b64decode(keys[envelope['key_id']],validate=True)
        signature=base64.b64decode(envelope['signature'],validate=True)
        if len(public)!=32 or len(signature)!=64 or key_id(public)!=envelope['key_id']:
            raise ValueError('Invalid signing material')
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        except ImportError:
            # Distribution Python on the Docker host needs no third-party
            # package. OpenSSL 3 provides the same Ed25519 verification.
            with tempfile.TemporaryDirectory(prefix='rime-release-verify-') as folder:
                root=Path(folder)
                der=bytes.fromhex('302a300506032b6570032100')+public
                pem=b'-----BEGIN PUBLIC KEY-----\n'+base64.b64encode(der)+b'\n-----END PUBLIC KEY-----\n'
                (root/'key.pem').write_bytes(pem);(root/'manifest').write_bytes(raw);(root/'signature').write_bytes(signature)
                result=subprocess.run(['openssl','pkeyutl','-verify','-pubin','-rawin','-inkey',str(root/'key.pem'),
                    '-in',str(root/'manifest'),'-sigfile',str(root/'signature')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                if result.returncode:raise ValueError('Signature mismatch')
        else:
            Ed25519PublicKey.from_public_bytes(public).verify(signature,raw)
    except Exception:
        raise UpdateError('release_signature_invalid') from None
