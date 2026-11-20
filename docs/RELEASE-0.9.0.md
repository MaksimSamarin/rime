# Rime 0.9.0

Rime 0.9.0 adds verified release updates and managed entry-server routing.

## Administration

- Version and release-update dialog with download, backup, installation and
  verification progress. Signed manifests, API/migration/scheduler readiness and
  a durable cutover barrier protect replacement. Failed candidates restore the
  previous container/data. Explicit compatible rollback keeps current user data.
- Guided node installation and recovery with preserved user identifiers, signed
  subscription URLs, multiple saved VPN listeners and registered proxies.
- Copying, checking and changing saved HTTP/HTTPS access. Proxy removal includes
  the owned runtime and any selected development tunnel rules.
- Automatic incident recovery, searchable users/tags and grouped traffic charts.
- Midnight console, readable resource boards and in-app guides/FAQ.

## Networking and operation

- The hub now uses the packaged Xray 26.6.1 engine required by the private Unix
  API. Loaded XRAY_JSON configurations receive mandatory private-address guards;
  an older explicit engine override that cannot create the socket fails closed.

- Qualified native Xray 26.6.1 image and separate panel probe executable, with
  pinned checksums and old/new REALITY client acceptance. A versioned runtime
  bundle and manifest are included for the deployment wizard.
- Ongoing node checks resolve current public DNS and pin the selected IP for
  each probe. Explicit migration destinations remain pinned to their planned IP.
- Development entry-server routing for existing VPN and proxy services, shared
  entries, isolated transport accounting and named management paths.
- Guided entry switching prepares and checks the new VPN/proxy route before
  publication, handles an unreachable previous entry and shows actual stage
  progress with recovery after refreshing the page.
- Complete VLESS control through a selected entry for qualified REST and RPyC
  nodes: user creation/editing/revocation, subscription continuity, usage,
  quotas, expiry and live logs. Entry changes, including when the former entry
  is unavailable, replace the controller endpoint while retaining the physical
  exit identity, running core and counter epoch.
- Both native management services authenticate the controller certificate.
  The internal Xray API uses a private Unix socket behind its public mTLS
  gateway. Prepublication checks reject missing control/API access and older
  runtimes without the authenticated-API capability.
- Cumulative usage collection on qualified native nodes with a core epoch commits
  counter positions and balances together, avoiding destructive reads and
  duplicate charging on idle polls, lost replies or transaction retries.
- Resource, event and traffic retention with bounded node/entry journals.
- Progress feedback for deployment jobs and configuration mutations.

## Deployment

Published update assets target Linux amd64, SQLite and one panel process.
The UI update action requires a one-time host-worker installation. See
[UPDATES.md](UPDATES.md). Development relay setup is described in
[TUNNELS.md](TUNNELS.md).

The host installer retains canonical container names across consecutive updates.
Update disk checks reserve at least the configured free-space floor. Release
assets are assembled in a draft and published only after the signed manifest.

Older native nodes require the qualified runtime upgrade before using the new
management path. Legacy/local APIs retain their existing reset-based metering.
Cumulative recovery assumes the same exit core remains running: an abrupt core
failure can lose its last unsampled interval. Manual usage-reset races and a
cold exit start while the panel is offline are outside this qualification.
An older reset-based collector must not start against existing cumulative counters.
The worker refuses this legacy downgrade; the explicit maintenance handover and
controller-compatibility requirements are described in [UPDATES.md](UPDATES.md).

The closed acceptance method in [TESTING.md](TESTING.md) uses the real panel,
native REST/RPyC services and Xray API, and includes entry-failure rollback,
user policy enforcement, cumulative accounting and API isolation.

The host updater installer now refuses a panel whose `SQLALCHEMY_DATABASE_URL`
is unset or relative instead of assuming `/var/lib/marzban/db.sqlite3`. Set an
absolute SQLite path on a persistent mount before installing it.

Review the existing service recovery profiles, certificate lifetime and current
client reachability before changing a live installation.
