# Testing

## Hub API isolation

`test_hub_api_security.py` exercises the actual file-backed `XRayConfig` parser,
mandatory private-IP/localhost rule ordering, preservation of user credentials
and special/excluded inbounds, legitimate public balancers and protected legacy
management indirection. It also covers owned stale-socket cleanup, active and
foreign socket rejection, symlinks, qualified executable selection, explicit
older overrides, fail-closed startup without a Unix listener, Unix gRPC channel
validation and REALITY key derivation without CLI-format assumptions.

The closed hub acceptance must use the qualified 26.6.1 executable, a private
direct `api.listen` socket and an ordinary VLESS user. A reachable TCP bait API
establishes the positive control. Requests through the VPN to both 127.0.0.1 and
localhost must fail, while a synthetic documentation-only public-IP echo works,
its bytes appear in user counters and direct Unix control can add a user. Also
test a public-target gRPC request with a balancer selecting the former API tag:
it must not reach management. Xray 24.12.31 is a negative compatibility case;
process startup alone must not be treated as a working protected API.

## Release update and entry routing

`tests/reality_compat.py` runs a real TLS 1.3 REALITY server 26.6.1 with clients
24.12.31 and 26.6.1, empty/Vision flows, synthetic keys and 32 KiB SHA256 payloads
inside `--network none`. It also checks rejection of an invalid short ID and
the qualified executable versions. The classical loopback decoy verifies
transport and version packaging. The hybrid Google-target case is additionally
qualified against the real endpoint during the native runtime acceptance.

`test_probe_binary.py` checks that every probe entry point chooses the packaged
client consistently while preserving explicit operator paths.

`test_relay_switch.py` exercises preparation before publication, unreachable old
entries, rollback, interrupted jobs, concurrent edits, DNS changes and late
transport observations. It also checks that GOST metadata-key normalization
after a restart permits owned cleanup while modified rules remain protected.
`test_relay_switch_api.py` exercises the sudo-only switch-plan/deploy HTTP
contract through the real ASGI routes. `relay_switch_ui.test.cjs` covers staged
progress, page refresh, duplicate submissions, failed checks and pending cleanup.

### Native VLESS management through an entry

`tests/relay_management_integration.py` qualifies the complete control path through
the real `main:app` HTTP application, its scheduled jobs, native node management
and Xray gRPC. Run it separately for REST and RPyC in its dedicated internal
Docker network, with independent entries, a physical exit, synthetic accounts
and certificates, and the release's qualified native image. Its fixture guards
reject an ordinary host invocation; it is not a standalone production command.
The fixture must allow unrelated local destinations so an operator's private-IP
block does not hide an API authentication failure.

`tests/relay_rpyc_integration.py` repeats the RPyC and gRPC management path across
two isolated GOST entries. `tests/native_user_reconnect.py` applies real runtime
user mutations and then reconnects the controller with synthetic UUIDs.

Acceptance covers these outcomes:

- Create a user, change its UUID, disable, enable and delete it through the
  panel. Confirm each change with a real VLESS connection while another user's
  established stream and the exit core process remain alive.
- Retain a previously issued signed subscription URL and user identity across
  healthy entry replacement and replacement after the old entry's forwarding
  and control services are unavailable. Verify the effective REST/RPyC and
  gRPC endpoints move to the new entry without restarting the exit core.
- Read live node logs through the panel websocket. Let the actual usage and
  expiry reviewers revoke users who exceed a quota or expire, then confirm
  denial with new client connections and continued access for another user.
- Persist real user and outbound usage with the same core epoch and durable
  cursor positions across entry switches. Repeated idle polls must not charge
  again. Pause and resume the panel while the exit stays running: existing and
  new sessions continue, and later cumulative collection catches up once.
- Separately block the proposed entry's native control and Xray API services
  while its VPN path works. Each attempted change must roll back before
  publication and retain the existing controller and route. A legacy runtime
  advertising no authenticated API must also be refused before an old
  controller operation can disrupt it.
- Return the former entry and complete its pending owned-rule cleanup without
  changing the selected controller, restarting the exit or disturbing another
  route's rules.
- Require the expected controller certificate on both public management
  services. Missing and foreign certificates must fail; an authenticated real
  `GetSysStats` through the selected entry must succeed. Through an ordinary
  VLESS user, a gRPC echo to an unrelated local service must work, while access
  to the private Unix API, its socket path and the public API via literal
  loopback or `localhost` without controller credentials must fail.

Supporting regressions are in `test_tunnel_management_endpoint.py`,
`test_relay_management_probe.py`, `test_native_api_bridge.py`,
`test_management_user_lifecycle.py`, `test_usage_node_isolation.py` and
`test_native_usage_cursors.py`. They cover physical-exit controller identity,
retired callbacks, authenticated readiness, private-socket ownership, deletion
of users without an administrator, healthy-node collection after another node
fails, and cumulative acceptance. Accounting fault injection includes a lost RPC
reply, transaction rollback and retry, changed core epochs, decreased counters,
concurrent collection, fractional/zero coefficients and reused numeric user IDs.

The cumulative guarantee applies only to qualified nodes exposing a stable live
core epoch. Legacy/local reset-based collection, a manual usage reset racing
with collection, and a cold exit start while the panel is offline are separate
cases. An abrupt core failure can lose its last unsampled in-memory interval.
Test summaries must identify the actual image and protocol used; passing the
Python regressions alone does not qualify the native transport boundary.

### Other release checks

`tests/test_updates.py`, `test_update_cleanup.py`, `test_update_health.py`,
`test_update_scheduling.py` and `test_update_storage.py` cover release identity,
queue races, coherent backup/restore, private file ownership, update barriers,
readiness, retained rollback sets and image-layer disk budgets.
`tests/update_integration.py` runs the real API and host worker against synthetic
release archives. It replaces a real container, verifies the old subscription,
then installs a deliberately failing candidate and verifies restored data/access.
The fixture network is internal and has no external route.

`tests/relay_integration.py` requires a disposable systemd/SSH host with Docker,
the qualified proxy image and Hysteria binary. It checks two entries with multiple
VLESS/Hy2 exits, HTTP/HTTPS authentication and TLS, proxy creation/edit/removal,
interrupted changes, exit replacement, peer stream preservation and operation
while the panel endpoint is stopped. Use synthetic identities and isolated
network namespaces for this harness.

The switch qualification stops the old forwarding service and drops its control
port, then checks VLESS, QUIC and authenticated HTTP/HTTPS through the new entry.
Returning the old entry must clean only the previous route's rules. A failed new
payload must preserve the published route and neighboring established TCP stream.
The fixture binds forwarding sockets to each simulated entry's loopback IP so
the two simulated hosts can independently reuse their public ports.

`test_relay_audit.py` covers forced direct publication with an unreachable entry,
explicit forget confirmation and credential revocation, planned grace and its
crash recovery, journaled proxy-rule withdrawal, malformed/port-hopping Hy2 links,
authenticated local observations and nonblocking telemetry quarantine. The
closed `relay_integration.py` additionally keeps real old VPN/HTTP/HTTPS payload
working during grace, expires it for owned cleanup, restores actual proxy rules
after a simulated prepublication interruption, withdraws a dead entry to direct
VLESS and forgets a stopped entry without remote operations. Its ordinary switch
cases explicitly select zero grace so they retain their original cleanup scope.

An authenticated observer check must reject missing/foreign local tokens while
the bundled GOST process reports exact real bytes. Observer delivery tests must
also accept a counter packet with no health field, quarantine a permanent
rejection, preserve retryable 401/403/429/5xx errors, and deliver fresh health on
its separate receipt stream without skipping older traffic counters.

`tests/relay_metering.py` runs with the image's bundled forwarding binary in
`--network none`. It checks exact cumulative bytes for an old held connection
and its hot replacement, separate service generations and duplicate delivery.
Prometheus export stays disabled. `test_relay_observer.py` covers restart,
monotonic retries, batching and local retention. Entry transport counters stay
separate from VPN user balances.

```sh
docker run --rm --network none -v "$PWD/tests:/code/tests:ro" \
  --entrypoint python rime:check /code/tests/relay_metering.py
python tests/update_integration.py --image rime:check --work /tmp/rime-update-lab
```

`tests/test_recovery.py` covers encrypted packets, key loss, legacy/nested archive
imports, shared decompression limits, client stripping, multi-transport server
keys and rebasing proxy ACL files. `tests/test_full_transfer.py` covers composite
VPN/proxy registration, generation/vault rollback, service port conflicts,
literal-IP endpoints and reconnect without a stop RPC to the source.
`tests/recovery_ui.test.cjs` covers stale asynchronous responses, clearing SSH
secrets, incomplete packets and upload limits.
`tests/events_docs.test.cjs` covers automatic active/history event rendering,
removal of manual workflow controls, documentation sections and native FAQ controls.
Browser acceptance includes direct `#docs` login, every guide anchor, keyboard FAQ,
navigation back to live data, reload and logout at desktop and mobile widths.

`tests/test_transfer.py` covers node identity, subscription metadata, durable
accounting transitions, rollback, controller interruption, concurrent edits,
retention and shared wizard plans. `tests/test_port_check.py` covers native
listeners, Docker publications, transport separation and replacement ownership.
`tests/provision_auth_ui.test.cjs` includes the transfer form and its locked
endpoint fields. Qualify a release with real SSH, Docker, TLS and VPN payloads
inside an isolated Linux environment before selecting a production node.

The unified console adds `tests/test_access.py` for per-node policy/config/host
filtering, identity reuse, tag reports and incident recovery comments. Run the
existing isolated `tests/e2e.py` harness with `CONSOLE_ACL=1` to additionally verify
selected-node TCP access, rejection on other Hy2/local Xray nodes, restart
persistence and restoration through an existing subscription URL. These tests
require the same isolated binaries and fixtures as the base E2E harness.

Autonomy regressions are in `tests/test_autonomy.py`, `tests/legacy_autonomy.py`
and `tests/native_autonomy.py`. The isolated transport harness verifies ongoing
TCP/UDP and new known users while the controller is stopped, local expiry,
persistent policy across an agent restart, and recovery without rebilling.
The native harness changes the controller-only API port while a VLESS stream
is open; the node must preserve its process and stream. It requires staged
REST node sources and a real Xray binary, and is not a production command.

`tests/test_reachability.py` checks separate/scoped client-probe credentials,
failure/recovery, stale results, bounded samples and replacement of node IDs.
Browser acceptance must include a healthy resource heartbeat with a failed
client probe: the client result stays failed, and only a successful client
payload resolves its incident. A node-local probe does not establish reachability
from a different network.

Fast checks from the repository root:

```sh
python -m pip install -r requirements-panel.txt
python -m unittest discover -s tests -p 'test_*.py' -v
node --test tests/*.test.cjs
node --check hy2bridge/web/app.js
node --check hy2bridge/web/console.js
node --check hy2bridge/web/monitoring.js
node --check hy2bridge/web/proxy.js
node --check hy2bridge/web/recovery.js
node --check hy2bridge/web/midnight.js
```

The transport test uses Linux socket/TLS behavior and is skipped on Windows.
`Rime checks` runs Python and console JavaScript checks on Linux. CI does not deploy,
connect to SSH targets or publish images. Image builds are local until release.

Self-service unit regressions cover direct address pinning, public/private target
validation, DNS and SAN mismatches, host-key changes, plan expiry, installation
capacity, interrupted-job retry and scoped rollback. Rollback must preserve the
management firewall whenever Docker cannot confirm container removal. Partial
image transfers are removed only by exact job-owned paths.

Closed integration acceptance uses an isolated controller, independent SSH target
namespaces and synthetic TLS/TCP/UDP echo services. It exercises prepared VLESS,
prepared Hy2, a bare Ubuntu target without Python/Docker, controller interruption,
real payload checks and authenticated HTTP/HTTPS proxies. No production database,
credentials or real subscription signing keys belong in this fixture.

Full-transfer acceptance must additionally stop the source host before restoring
multiple VLESS transports or legacy Hy2 together with its proxies. Compare all
existing subscription formats byte for byte, test an ordinary user's old client
configurations, reject revoked backup credentials, check every retained proxy
account and verify custom ACL denial with an actual request. Confirm exact
server TLS/REALITY/obfuscation keys and NCSA hashes. Inject proxy failure after
registration switches, interrupt the controller during cutover and retry the
same candidate through the UI. A successful VPN probe alone is insufficient to
qualify proxy configuration recovery.

Systemd acceptance must use a real PID-1 systemd host with Docker and SSH.
Exercise port and primary-credential changes, retention of additional users and
ACLs, a failed forwarding check and a controller outage while the source proxy is
stopped. Wait for the shipped 180-second recovery timer, then verify HTTP/HTTPS
and old VPN clients from an independent test container while the controller is
still stopped. Restart the controller, retry with fresh SSH access and confirm
cleanup and timer cancellation. Include Python installed under `/usr/local/bin`,
legacy Squid default PID paths and a saved VLESS inbound without a published host.

The integrated Midnight console keeps one set of routes and API clients.
Browser acceptance covers every main route at desktop and 375 px, recovery
import/capture, keyboard close, transfer retry, persistent navigation from node
reports, reduced motion and the fixed horizon after a long scroll. Route timings
measured through a local test adapter include its process overhead and do not
represent production latency.

The image job also runs `tests/console_creation.py` in its newly built image with
no external network, a temporary database and synthetic accounts. It verifies
VLESS inbound defaults, external Hy2 links, real VLESS payload, selected-node
filtering, disabled creation, editing and previously issued URLs after restart.
This regression harness does not require separate Hy2 binaries or lab certificates.

`tests/ui_routes.py` checks the default and custom legacy dashboard redirects,
subscription icons, the API, both CLI entry points and the absence of the retired
frontend. It also runs in the isolated image job with a temporary database.

Node-quota regression tests are in `tests/test_node_quotas.py`. The isolated E2E
harness additionally supports `NODE_QUOTAS=1`: Hy2/VLESS node-wide enforcement,
other-node availability, old subscription continuity, persistence across panel
restart, manual reset and an accelerated scheduled boundary in the private fixture.

The isolated E2E suite also starts a dedicated Hysteria client as the monitoring
tunnel. It verifies an echoed payload, stops that client to produce
`traffic_failed`, starts it again, and confirms that a successful recheck resolves
the incident. Browser QA covers direct hash routes, asset cache headers, user
typeahead, node edit persistence, manual checks from node and incident screens,
and desktop/mobile overflow.

`tests/e2e.py`, `core_crash.py`, `provision_traffic.py`, and `restore.py` are inherited
lab harnesses, not generic production tools. They require a prepared isolated
Linux lab, pinned Xray/patched Hysteria binaries and synthetic data. They must
never be run against a production database or Docker namespace. The legacy-link
fixture uses reserved `.invalid` domains. No deployment credentials are included.

`test_traffic_groups.py` verifies bounded top groups, preserved totals, tag
overlap, deleted/reused account identities and missing hours. `traffic_groups.test.cjs`
checks grouped drawing, line gaps and keyboard readouts. `node_refresh.test.cjs`
checks that background refresh retains the visible node for recovery/transfer,
while changing nodes disables actions until the new details arrive. Full-transfer
tests also reject an attempted connection to an unavailable source: saved Hy2
and VLESS configurations must suffice for preparing the replacement.

On Linux, `test_port_check.py` creates a real TCP `TIME_WAIT` socket after a
closed session. Rebinding must succeed, while live reusable TCP/UDP listeners
and foreign Docker publications remain protected. This prevents a safe proxy
replacement from being rejected only because the old service recently handled
traffic.

To reproduce core tests, check out Hysteria `app/v2.12.3` into a separate directory,
apply `python core-patches/apply.py <source>`, copy `durable_test.go` into
`extras/trafficlogger/fleet_durable_test.go`, and run Go tests in that module.
Retain the upstream LICENSE when packaging. The node binary must be named
`hysteria-fleet`; an upstream unpatched binary does not provide durable accounting.
