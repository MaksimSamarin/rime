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

## Hub API and private destinations

Every loaded `XRAY_JSON` passes through mandatory hub protection. The panel
uses Xray 26.6.1's direct `api.listen` Unix socket, mode 0600 in an owned 0700
directory. There is no management inbound or API routing handler that a VPN
user's routing rule or a catch-all balancer can select. The API's logical tag
remains required by Xray's configuration builder; it is not a public listener.

The effective router uses `IPOnDemand` and places private-address and localhost
guards before operator-supplied domain or catch-all rules. An `AsIs` value in
the source file cannot defer that protection until after a public allow rule.
Other user inbounds, credentials and ordinary outbound/balancer settings remain
attached to the existing configuration.

The default hub executable prefers the packaged qualified hub/probe runtime.
An explicit `XRAY_EXECUTABLE_PATH` is retained. Xray 24.12.31 accepts some Unix
listener configurations while silently creating no listener; it is unsuitable
for this hub API. Startup terminates a core that fails to create the protected
socket and never reports it ready. No unauthenticated TCP fallback is started.
REALITY public keys are derived from the saved private key independently of
version-specific `x25519` command output, preserving existing key material.

Legacy native nodes still expose a TLS API on port 62051 until their runtime upgrade.
Their external source-IP restriction remains necessary, but it alone cannot
protect against the node's own VPN user connecting to loopback. Configurations
sent by this controller retain the private-destination guards; before sending
to a legacy runtime, the controller also validates management-tag indirection,
including balancer prefixes/fallbacks and proxy chains. An unsafe configuration
is rejected. Legacy runtimes cannot use the new entry-management path until
their authenticated direct-API capability is available.

A still-running older deployment retains its previous configuration until an
approved controller/runtime update and reconciliation. Preparing these source
changes does not remotely repair that deployment. Qualify hub startup, local
API isolation, ordinary VPN payload, user mutations and metering in a closed
environment before rollout. See [TESTING.md](TESTING.md).

## Deployment wizard

Requires an approved SSH target, a verified host fingerprint, free ports and a
reachable HTTPS panel URL. The plan checks Python and Docker and includes their
installation on supported Debian/Ubuntu servers when needed. TLS uses supplied
PEM files or a configured panel certificate that covers the node hostname.
DNS is prepared by the operator. The wizard's configuration includes these fields.

- `allowed_hosts`: exact approved targets.
- `panel_url`: HTTPS URL reachable from new nodes.
- `hy2_bundle`: archive containing `hy2bridge/` and patched `hysteria-fleet`.
- `python_image`: verified runtime pinned with `@sha256:...`.
- `vless_template`: image digest and an existing inbound's `inbound_tag`,
  `inbound_port`, `certificate_path`, `key_path`, `service_port`, `api_port`.

### Qualified native runtime

The `node-source` image target contains Xray 26.6.1 and the current native lifecycle
helpers. The runtime retains compatibility with the qualified 24.12.31 and 26.6.1
clients. The version is pinned with both archive and executable checksums.

```sh
docker build --target node-source --tag rime-node:0.9.0 .
python scripts/export_node.py --image rime-node:0.9.0 --output dist/native
```

The export produces a versioned Docker-save archive, checksums and
`rime-node-runtime.json`. Use its `image_id` for **both** `python_image` and
`vless_template.image`, and use its archive path/digest for `base_image_bundle`
and `base_image_bundle_sha256`. The common image also supplies Python for Hy2;
the patched Hysteria executable comes from `hy2_bundle`.

Set `vless_template.runtime_dir` to `/opt/rime-node-runtime` in the panel image.
Those files match the lifecycle code already baked into the native target.
Keep the database, signing material, user identifiers and saved node profiles
when updating the runtime configuration.

The panel image includes the qualified probe executable at `/opt/rime-probe/xray`.
It is the default for manual, periodic, installation, transfer and relay checks.
Explicit `client_probe_xray_binary` and `xray_binary` settings take precedence.
Set both to this path when updating an installation with older explicit paths.
Persisted fleet configuration is reviewed and applied alongside the native
bundle, including both image references. The version dialog's release assets
include this bundle and its runtime manifest.

Never copy `lab_network` overrides into production. Installs use dedicated
`~/.local/share/fleet-nodes/<id>` directories and owned containers. Failure removes
only owned registration/container; diagnostic files remain.

Run Hy2 with `hy2bridge.supervisor`, persistent `spool` and `traffic_wal`,
`durable: true`, scoped credentials, local stats/auth endpoints and verified HTTPS.
The supervisor recovers the local agent without stopping a live Hysteria engine.
Controller freshness is diagnostic; it does not expire saved authorization.
Policies persist in the node spool database. Known expiration and remaining
user budgets are enforced locally; unknown keys are denied. Usage delivery can
resume after an outage without clearing counters. The remaining allowance is
based on the last central policy, so disconnected nodes can temporarily exceed
a shared global limit. This is not a strict distributed quota allocator.

For an existing standalone Hy2 node, `hy2bridge.legacy_auth` uses its observer
spool read-only plus the uncollected counter tail. It preserves `/` and `/auth`
and stores policy in a separate `auth_policy_db`. Deploy with a verified scoped
policy before switching the bridge; a shadow configuration can set `enforce:
false`. Keep the existing Hysteria configuration and client credentials.

`node-runtime/apply.py` patches a staged v0.5 REST node source: losing a controller
session does not stop Xray, and unchanged effective configuration attaches to a
running engine. Check active bind mounts: an older mounted `rest_service.py`
must not override the qualified image. Explicit stop and changed core settings
retain their stop/restart behavior. This does not add node-local VLESS expiry,
durable counters or offline native-node bootstrap.

Client reachability is a separate signal from resource telemetry and management.
Configure `client_probes` with an ID, named origin, a separate credential and an
explicit list of node IDs. Run `python -m hy2bridge.client_probe --config ...`
on that origin with Xray/Hysteria client binaries and an existing dedicated test
account. The sender verifies an HTTPS payload and expected egress, bypasses
environment proxies and checks configured direct target addresses. The network
gateway must also route those destinations directly. A local process heartbeat
cannot report this result. Results expire after three minutes; sender failure
becomes unknown, not proof of a dead VPN. Do not hide direct failures with
inter-node relays.

Closed diagnostics retain at most 30 days/5000 rows; open incidents and accounting
remain. Resource history keeps seven days. Client-probe reports overwrite the
previous sample per node/origin rather than creating an unbounded error log.

## End-to-end node check

The node agent can verify payload delivery through a dedicated local VPN client
tunnel. Configure a loopback-only forward on the node and add it to the agent:

```json
"traffic_probe": {"host": "127.0.0.1", "port": 18101, "bytes": 2048}
```

The forward must use a dedicated probe account and terminate at a fixed echo
service. An agent-side check queues this local test. A byte-for-byte echo opens
or resolves `traffic_failed`. A TCP connect to the public VPN port alone cannot
confirm payload delivery.

The primary node and `client_unreachable` incident actions request a separate
client check from the panel's own network. They use the configured test account,
strict TLS and a real HTTPS response with the expected egress IP. The result
shows origin, target, time and stage. Missing configuration and expired results
are shown as unknown. An agent heartbeat cannot substitute for this check.

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
reconnect clients. Hy2 endpoints are added to raw link lists, sing-box and Mihomo
(Clash Meta) subscriptions. Existing outbounds and routing remain. Classic Clash,
Outline and Xray JSON retain their existing protocol support. Unsupported Hy2 URI
extensions fail explicitly instead of silently losing transport or TLS settings.

## Self-service node installation

The operator creates the DNS A record before opening the wizard. New targets
must be directly reachable from the panel over SSH and use a single IPv4 address.
The current wizard rejects AAAA records. Basic installation supports root on
Debian/Ubuntu x86_64. Other already-prepared Docker hosts are accepted only when
the preflight checks pass. The wizard reports prerequisites before deployment.

Missing Python 3 and Docker packages are installed after plan confirmation.
The installer preserves existing services and only creates labelled containers
and files for its own job. It uses a pinned SSH host key, qualified local image
bundles and automatic panel TLS material whose SAN covers the supplied domain.
Custom PEM material can be entered explicitly. DNS management stays with the
operator. Certificates installed on nodes require renewal before expiration.

The panel protects its own address from installation. VLESS management ports
are restricted to the configured controller IPv4. A new node becomes visible in
subscriptions after fresh resource telemetry and a successful client payload
check. The existing UUIDs and issued subscription URLs remain usable.

Plans keep SSH credentials only in memory for ten minutes. Job status and
nonsecret retry context survive refresh and controller restart. After an
interrupted install, retry requires fresh SSH credentials and cleans only the
previous job's resources. The default maximum is two concurrent installations.
Completed cleanups retain their audit record. An unreachable target remains
failed for explicit recovery.

## HTTP and HTTPS forward proxies

The node card can install an additional authenticated Squid service. HTTP uses
CONNECT on a plain proxy connection. HTTPS encrypts the connection to the proxy
as well. An administrator can copy the saved connection URLs and edit an
installed proxy from the node card. The panel encrypts saved passwords with its
vault key. The proxy server stores NCSA password hashes. Legacy hash-only
accounts retain their passwords, and copying their plaintext credentials requires
the administrator to supply and verify the password once. The installer verifies both
rejection of anonymous requests and actual HTTPS forwarding before success.

The guarded systemd import supports HTTP 3128 with optional HTTPS 443. It reads
the actual listeners, retains the existing NCSA account and destination-port
policy, and ignores ports owned by unrelated services. A certificate-renewal
adapter is required when importing an existing TLS listener. An HTTP-only
service does not acquire an HTTPS listener during import. The old systemd
service is disabled only after a successful authenticated payload check; a local
systemd watchdog restores it on failure.

## Traffic charts and recovery readiness

`GET /api/fleet/traffic?detail=false&group_by=protocol|node|tag|user` keeps the
original totals, filters and protocol series. Non-protocol groupings additionally
return `chart_groups` and `chart_series`. Up to six groups are shown; larger
reports retain the five largest and aggregate all remaining traffic as
**Остальные**. Grouped lines and totals use one read transaction. Missing hourly
records remain unknown, rather than becoming fabricated zero measurements.

Tag grouping uses current, incarnation-checked user metadata. A multi-tag user's
traffic belongs to each tag, so these series can overlap. Untagged, deleted and
obsolete account incarnations cannot inherit another account's tags. The chart
discloses this rule, and the report's overall total remains unchanged.

A complete recovery profile allows both Hysteria2 and VLESS to move after the
old VPS has been deleted. Only the replacement needs SSH access. New managed
installations retain the VPN and proxy configuration automatically; older nodes
must be captured by direct SSH or imported from a configuration archive before
the source is lost. The **Комплект восстановления** screen checks missing VPN
inbounds and registered proxies. Back up the panel database together with its
vault key. A never-saved private key cannot be reconstructed from monitoring.

Proxy credentials and traffic are separate from VPN subscription quotas. OS
network telemetry includes all services. Proxy authorization is local and keeps
working when the panel stops. Node removal from the panel retains remote VPN and
proxy software until separately removed.

## Availability and retention

Native node observers run in Docker next to the node container. The installer
binds the node host's `/proc/meminfo`, `stat`, `uptime`, `loadavg` and
`cpuinfo`, and on cgroup v2 hosts also `cpu.stat` and `cpu.max` of the host's
cgroup root. Inside an LXC container these files describe the container, not
the physical host. CPU usage is taken from the cgroup counter when it is
present, because some lxcfs builds report system time in `/proc/stat` that the
container did not use. Load average is the provider's value unless lxcfs
virtualizes it. Observers installed before 0.9.5 keep their original mounts
until they are installed again.

The console's **Документация** tab contains administrator guides, troubleshooting
and FAQ within the shared navigation. It is static and pauses background API
polling while being read.

The event list shows active incidents and recovery history. Repeated failures
update one incident's counter. A matching successful check closes it automatically.
With **Только активные** enabled, recovered incidents disappear from the list.
The node card links to actual client checks. Earlier action/comment records remain
available to compatible API clients, while the console uses the automatic lifecycle.

Manual and scheduled checks of active managed nodes resolve their current public
DNS addresses for each check. A saved deployment IPv4 may describe the previous
address after an IP change. Each check pins its selected DNS answer for the whole
connection, preserves TLS SNI and verifies actual egress traffic. All preserved
VPN hostnames must share an address. Initial installation and replacement continue
to verify the explicitly selected destination server before publication.

Hy2 authenticates known users from its persisted local policy while the panel is
offline. A running VLESS core retains its authorized accounts in memory.
Existing flows and new connections continue. Cold-starting the VLESS container
still requires the panel to supply its configuration. Retrieving subscriptions,
adding users and delivering changed policy require the panel. Locally enforced
expiry and quotas still apply. A shared quota across isolated nodes cannot be
synchronously coordinated during a network partition.

The verified VLESS user-reconciliation capability requires the current native
runtime. Existing older runtimes need a controlled one-time container upgrade.
Afterwards, account add, UUID replacement and removal are reconciled through
live TLS gRPC queries without restarting an otherwise equivalent core. Static
configuration changes and unsupported account schemas retain explicit restart
behavior. An uncertain management transport preserves the running core.

Resource history and raw samples retain seven days with a 250,000-row cap each.
Meter-gap diagnostics retain 90 days and at most 10,000 rows. Closed incidents
retain 30 days and at most 5,000 rows. Completed manual checks retain seven days,
with at most 500 client checks. Successful unregistered jobs retain 30 days and
rolled-back jobs 90 days. Active registrations and unresolved cleanup jobs stay
available for recovery. Financial hourly history and cumulative totals remain.

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

## Replacing a failed node

Open the node card and choose **Перенести на новый сервер**. Point the existing
DNS name at the replacement IPv4, then provide its direct SSH credentials and
verify its host-key fingerprint. The wizard retains the original node ID,
subscription endpoints, user credentials, assignments, tags and history.
Fresh host telemetry and an authenticated VPN payload check are required before
the transfer succeeds. Source services and data are preserved for separate recovery.

The transfer restores a complete saved service profile. It supports multiple
VLESS inbounds and transports, TLS and REALITY server keys, Hysteria2 HTTP-auth
configurations, obfuscation settings and authenticated HTTP/HTTPS proxies.
Proxy NCSA accounts, custom access rules, include files and referenced ACL data
are retained. The node and its proxies switch registration together. Every
issued VPN variant and each proxy mode must pass an authenticated payload check.
Original proxy hashes are restored after qualification and the temporary test
password is revoked before success.

Saved VLESS profiles also retain manual inbounds that have no published host.
Their existing ports remain available, and qualification checks them using the
saved transport configuration. The probe account needs access to every restored
tag, and those tags must still exist in the controller's authorized configuration.
Published subscription hosts remain scoped to their existing bindings.

The node card's **Комплект восстановления** shows whether the saved profile is
complete. Ordinary managed VPN/proxy installations save their configuration
automatically. For older manual deployments, import the configuration tar.gz once
or capture it directly over pinned SSH while the source is available. Capture
reads data and leaves source services running. File-backed configurations,
certificates and NCSA files must be present in the packet. A legacy Xray process
started with an unrecoverable stdin configuration needs its startup archive.
Missing server keys and unreported usage require a backup of the lost server.

Recovery packets are encrypted in the panel database. Back up the database and
the proxy vault key together. Losing the key requires restoring it from backup.
Import accepts at most 64 MiB, shares a 128 MiB decompression budget across nested
archives and limits the stored configuration packet to 8 MiB. Archives are
parsed as data. Their paths and scripts are never extracted or executed.

A failed transfer restores the previous VPN and proxy registrations together
and removes only its owned candidate containers. A controller restart recovers
an interrupted registration from the persisted snapshot. Reopening the transfer
offers cleanup and retry with fresh SSH credentials. Concurrent registration
changes preserve the candidate for explicit reconciliation. DNS rollback is
performed by the operator. Replacement-server SSH and initial client checks use
direct routes. An explicitly selected development entry can carry subsequent
management and proxy operations. Its named route remains visible and the exit's
SSH fingerprint is still checked. See [TUNNELS.md](TUNNELS.md).

Keeping the original DNS names preserves existing client endpoints. Literal-IP
endpoints are rewritten transactionally while retaining the subscription URL.
Those clients must refresh the subscription contents. An HTTPS proxy whose
certificate identifies only the old IP needs a valid certificate for its new
endpoint. TLS identity checks remain enabled. A legacy static Hy2 password or
userpass setup requires an explicit saved mapping to panel users before adoption.
The fleet's HTTP-auth configuration already provides that identity mapping.

Editing an existing managed proxy retains its additional accounts and access
rules. Replacement uses a local systemd rollback timer and requires a running
systemd host. Preflight reports this requirement before any service is stopped.
The recovery timer uses the remote worker's Python interpreter. Imported Squid
profiles use an explicit PID file in the container's writable runtime directory,
including profiles saved by an earlier release.

Hysteria replacement starts a new node journal while retaining charged usage,
hourly history and node quota consumption. The previous journal cursor and
cumulative baseline are retained for rollback. Unsent usage from a lost host
requires its journal or backup. Include the panel database, TLS files and proxy
vault key in the normal recovery checkpoint.

Node and proxy installers check native sockets and published Docker ports by
transport during preflight and immediately before launching a container.
VLESS and an HTTPS proxy require different TCP ports on the same IPv4.
Hysteria UDP 443 can coexist with an HTTPS proxy on TCP 443.
