"""Exercise REALITY with old and current clients inside a network-isolated container.

Run with the release image and a read-only mount of this directory at /code/tests
using Docker's --network none option. All identities and certificates are temporary.
"""

import argparse
import base64
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.x509.oid import NameOID


LOOPBACK = "127.0.0.1"
SERVER_NAME = "decoy.lab.invalid"
PAYLOAD_BYTES = 32 * 1024
EXPECTED_VERSIONS = {"server": "26.6.1", "old_client": "24.12.31", "new_client": "26.6.1"}


def receive_exact(connection, size):
    received = bytearray()
    while len(received) < size:
        part = connection.recv(size - len(received))
        if not part:
            raise ConnectionError("The forwarding stream closed before the payload completed")
        received.extend(part)
    return bytes(received)


def unused_port():
    with socket.socket() as listener:
        listener.bind((LOOPBACK, 0))
        return listener.getsockname()[1]


def write_config(path, config):
    path.write_text(json.dumps(config), encoding="utf-8")
    path.chmod(0o600)


def synthetic_identity():
    key = x25519.X25519PrivateKey.generate()
    private = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return {
        "id": str(uuid.uuid4()),
        "private_key": base64.urlsafe_b64encode(private).decode().rstrip("="),
        "public_key": base64.urlsafe_b64encode(public).decode().rstrip("="),
        "short_id": os.urandom(8).hex(),
    }


@contextmanager
def tls_echo(root):
    """Provide a real TLS 1.3 decoy and a TLS application destination on loopback."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, SERVER_NAME)])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(SERVER_NAME)]), False)
        .sign(key, hashes.SHA256())
    )
    certificate_path = root / "certificate.pem"
    key_path = root / "certificate-key.pem"
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    key_path.chmod(0o600)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.set_ecdh_curve("X25519")
    context.set_alpn_protocols(["h2", "http/1.1"])
    context.load_cert_chain(certificate_path, key_path)

    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                self.request.settimeout(5)
                with context.wrap_socket(self.request, server_side=True) as connection:
                    while body := connection.recv(65536):
                        connection.sendall(body)
            except (OSError, ssl.SSLError):
                # REALITY also opens this listener for its decoy handshake.
                pass

    server = socketserver.ThreadingTCPServer((LOOPBACK, 0), Echo)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], certificate_path
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def server_config(identity, flow, port, decoy_port):
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": LOOPBACK,
            "port": port,
            "protocol": "vless",
            "settings": {
                "clients": [{"id": identity["id"], "flow": flow}],
                "decryption": "none",
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "dest": f"{LOOPBACK}:{decoy_port}",
                    "serverNames": [SERVER_NAME],
                    "privateKey": identity["private_key"],
                    "shortIds": [identity["short_id"]],
                },
            },
        }],
        "outbounds": [{
            "protocol": "freedom",
            "settings": {
                # The lab's application lives on loopback. Production policy is separate.
                "finalRules": [{"action": "allow", "ip": [f"{LOOPBACK}/32"]}],
            },
        }],
    }


def client_config(identity, flow, port, server_port):
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": LOOPBACK,
            "port": port,
            "protocol": "socks",
            "settings": {"auth": "noauth"},
        }],
        "outbounds": [{
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": LOOPBACK,
                    "port": server_port,
                    "users": [{"id": identity["id"], "encryption": "none", "flow": flow}],
                }],
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "serverName": SERVER_NAME,
                    "fingerprint": "chrome",
                    "publicKey": identity["public_key"],
                    "shortId": identity["short_id"],
                    "spiderX": "/",
                },
            },
        }],
    }


@contextmanager
def running_core(binary, config_path, log_path, port):
    with log_path.open("w", encoding="utf-8") as log:
        process = subprocess.Popen(
            [binary, "run", "-c", str(config_path)], stdout=log, stderr=log
        )
        try:
            deadline = time.monotonic() + 5
            while True:
                if process.poll() is not None:
                    raise RuntimeError("Xray exited during startup")
                try:
                    with socket.create_connection((LOOPBACK, port), timeout=0.2):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("Xray did not open its loopback listener")
                    time.sleep(0.05)
            yield
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)


def verify_payload(socks_port, destination_port, certificate_path, timeout=5):
    context = ssl.create_default_context(cafile=str(certificate_path))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    with socket.create_connection((LOOPBACK, socks_port), timeout=3) as connection:
        connection.settimeout(timeout)
        connection.sendall(b"\x05\x01\x00")
        if receive_exact(connection, 2) != b"\x05\x00":
            raise RuntimeError("SOCKS authentication negotiation failed")
        connection.sendall(
            b"\x05\x01\x00\x01" + socket.inet_aton(LOOPBACK)
            + destination_port.to_bytes(2, "big")
        )
        reply = receive_exact(connection, 4)
        if reply[:3] != b"\x05\x00\x00":
            raise RuntimeError("SOCKS forwarding request failed")
        address_size = {1: 4, 4: 16}.get(reply[3])
        if address_size is None:
            raise RuntimeError("Unexpected SOCKS bind address type")
        receive_exact(connection, address_size + 2)
        with context.wrap_socket(connection, server_hostname=SERVER_NAME) as application:
            payload = os.urandom(PAYLOAD_BYTES)
            application.sendall(payload)
            received = receive_exact(application, len(payload))
            if hashlib.sha256(received).digest() != hashlib.sha256(payload).digest():
                raise AssertionError("Forwarded payload checksum differs")
            return len(received)


def core_version(binary):
    version = subprocess.check_output([binary, "version"], text=True, timeout=5)
    return version.splitlines()[0]


def reject_invalid_identity(root, identity, binary, server_port, destination_port, certificate_path):
    invalid = {**identity, "short_id": f"{int(identity['short_id'], 16) ^ 1:016x}"}
    client_port = unused_port()
    client_path = root / "invalid-client.json"
    client_log = root / "invalid-client.log"
    write_config(client_path, client_config(invalid, "", client_port, server_port))
    with running_core(binary, client_path, client_log, client_port):
        try:
            verify_payload(client_port, destination_port, certificate_path, timeout=2)
        except (OSError, RuntimeError):
            print("PASS invalid REALITY shortId rejected", flush=True)
            return {"invalid_short_id_rejected": True}
    raise AssertionError("An invalid REALITY shortId forwarded the application payload")


def qualify(server_binary, old_client, new_client):
    versions = {
        "server": core_version(server_binary),
        "old_client": core_version(old_client),
        "new_client": core_version(new_client),
    }
    for role, expected in EXPECTED_VERSIONS.items():
        if versions[role].split()[1] != expected:
            raise RuntimeError(f"Expected {role} Xray {expected}, received {versions[role]}")
    results = []
    authentication = {}
    with tempfile.TemporaryDirectory(prefix="rime-reality-compat-") as temporary:
        root = Path(temporary)
        identity = synthetic_identity()
        with tls_echo(root) as (destination_port, certificate_path):
            for flow in ("", "xtls-rprx-vision"):
                server_port = unused_port()
                server_path = root / "server.json"
                server_log = root / "server.log"
                write_config(server_path, server_config(identity, flow, server_port, destination_port))
                try:
                    with running_core(server_binary, server_path, server_log, server_port):
                        for label, binary in (("old_client", old_client), ("new_client", new_client)):
                            client_port = unused_port()
                            client_path = root / "client.json"
                            client_log = root / "client.log"
                            write_config(client_path, client_config(identity, flow, client_port, server_port))
                            try:
                                with running_core(binary, client_path, client_log, client_port):
                                    size = verify_payload(client_port, destination_port, certificate_path)
                            except Exception as error:
                                raise RuntimeError(
                                    f"{label}, flow={flow or 'empty'} failed\n"
                                    + client_log.read_text(encoding="utf-8")[-4000:]
                                ) from error
                            results.append({"client": label, "flow": flow, "bytes": size, "sha256_matches": True})
                            print(f"PASS {label} flow={flow or 'empty'} TLS1.3 payload={size} SHA256", flush=True)
                        if not flow:
                            authentication = reject_invalid_identity(
                                root, identity, new_client, server_port, destination_port, certificate_path
                            )
                except Exception as error:
                    raise RuntimeError(
                        f"REALITY compatibility failed for flow={flow or 'empty'}\n"
                        + server_log.read_text(encoding="utf-8")[-4000:]
                    ) from error
    return {
        "versions": versions,
        "results": results,
        "authentication": authentication,
        "synthetic_keys_only": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server-binary", default="/opt/rime-probe/xray")
    parser.add_argument("--old-client", default="/usr/local/bin/xray")
    parser.add_argument("--new-client", default="/opt/rime-probe/xray")
    args = parser.parse_args()
    print(json.dumps(qualify(args.server_binary, args.old_client, args.new_client)))


if __name__ == "__main__":
    main()
