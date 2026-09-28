# Operations and migration

Rime currently supports SQLite and exactly one panel process. The controller locks
`<database>.fleet.lock`; MySQL and multiple workers are unsupported. Existing
environment variables, `/api`, subscription routes and `/var/lib/marzban` mounts
are preserved. `/fleet` is the unified console for users, reports and infrastructure.
`/dashboard/` redirects to its Users page. See [console workflow](CONSOLE.md).
Infrastructure requires a sudo admin. Tokens are never passed in URLs.

Run `alembic upgrade head` followed by `python main.py`. The Docker entry point
uses `&&` so failed migrations prevent startup.

The console is served directly from `hy2bridge/web`; no frontend build is needed.
`install_service.sh` creates `rime.service` by default. Set `SERVICE_NAME=marzban`
explicitly only when maintaining that existing unit name. The script writes the
unit and reloads systemd; it does not enable, start or migrate running services.
The `rime-cli.py` and legacy `marzban-cli.py` entry points share the same commands.

`RIME_FLEET_CONFIG` points to a mode-600 JSON file; `HY2_PANEL_CONFIG` is a legacy
alias. Without either, reporting starts with no Hy2 credentials or SSH targets.
Configuration changes require restart. Minimal config:

```json
{"node_tokens": {}, "safe_period_reset": false, "provision": {"allowed_hosts": []}}
```

Each existing Hy2 node needs a unique random token of at least 32 characters.
Newly provisioned tokens are hashed in the panel DB. SSH credentials live only
in memory; plans expire in 10 minutes. Never commit real configuration.

Enable `safe_period_reset` only after **all** used Hy2 nodes run durable agents.
The reset drains sessions and ingests final usage; offline nodes cause HTTP 409.
Do not run an unpatched reset job alongside this controller.

## Deployment wizard

Requires an explicit SSH target allowlist, verified host fingerprint, existing
Docker, free ports, a reachable HTTPS panel URL and supplied valid TLS PEM files.
It does not install Docker or issue ACME certificates. `provision` settings:

- `allowed_hosts`: exact approved targets.
- `panel_url`: HTTPS URL reachable from new nodes.
- `hy2_bundle`: archive containing `hy2bridge/` and patched `hysteria-fleet`.
- `python_image`: verified runtime pinned with `@sha256:...`.
- `vless_template`: image digest and an existing inbound's `inbound_tag`,
  `inbound_port`, `certificate_path`, `key_path`, `service_port`, `api_port`.

Never copy `lab_network` overrides into production. Installs use dedicated
`~/.local/share/fleet-nodes/<id>` directories and owned containers. Failure removes
only owned registration/container; diagnostic files remain.

Run Hy2 with `hy2bridge.supervisor`, persistent `spool` and `traffic_wal`,
`durable: true`, scoped credentials, local stats/auth endpoints and verified HTTPS.
The supervisor stops its core when the control lease expires. Defaults: 1-second
polling, 5-second auth TTL, 15-second supervisor lease.

## End-to-end node check

The node agent can verify payload delivery through a dedicated local VPN client
tunnel. Configure a loopback-only forward on the node and add it to the agent:

```json
"traffic_probe": {"host": "127.0.0.1", "port": 18101, "bytes": 2048}
```

The forward must use a dedicated probe account and terminate at a fixed echo
service. `Проверить VPN-трафик` queues a check for the agent. A byte-for-byte echo
opens or resolves `traffic_failed`. A TCP connect to the public VPN port alone is
never a successful check. Nodes without this agent show `Не проверялся` and reject
manual checks instead of returning a false green status.

Native VLESS node edits update Marzban's node record and schedule a reconnect.
For managed Hysteria2 nodes, domain, VPN port and publication state edit the
subscription inventory; changing the remote service still requires a controlled
redeployment.

## Subscription continuity

Preserve subscription domain/path, signing material, user creation dates, UUIDs,
SNI/ports, custom templates and existing link additions. This public fork does not
contain private legacy `share.py` customization: port that logic explicitly.
Never install the synthetic fixture on production. Verify old issued URLs remain
usable; freshly generated URLs need not be byte-identical. Core restarts can
reconnect clients. New Hy2 endpoints currently support v2ray/link-list subscriptions;
all Clash/sing-box variants are not claimed.

## Accounting, backup and rollback

Hy2 accounts accepted payload after fsync and before forwarding, not confirmed
delivery or IP/QUIC overhead. A crash can charge accepted but unsent bytes.
Polling quotas can overshoot under load. Hours represent posting time. Per-user
Xray reports combine directions; node quotas use raw directional node counters.
Missing historic data cannot be reconstructed.

Before migration, checkpoint the panel SQLite with `.backup`, config, signing
material, binaries and every node's spool/WAL. Pilot one node and actual clients.
Restore a whole checkpoint or reconcile explicitly: never restore an old panel
DB against newer journals or silently replace a lost spool.

## Qualification

The baseline integration passed isolated Linux lab checks: 51 integration checks,
25 Python tests, 4 Go journal tests, and 600 seconds with 8 clients and exact
counters after SIGKILL. These are baseline results, not a production SLA or a
claim that every fork build has passed them. Consult the PR for rerun checks.
Public-network behavior, real client applications and sustained observation
remain deployment-specific pilot gates. Controlled production migration and
rollback rehearsals have been completed; they do not qualify every installation.


Native node monitoring materializes SQLite query results before remote RPCs.
Do not keep active read cursors during network operations: production may use
SQLite rollback journal mode, where such readers block accounting commits.
