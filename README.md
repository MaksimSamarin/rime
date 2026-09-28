# Rime

**VPN infrastructure management**

VLESS + Hysteria2, shared traffic accounting and quotas, monitoring, reports and
SSH node deployment. Rime is a fork of Marzban **0.8.4**.

![Rime](docs/brand/rime.svg)

**0.2.0-rc6: release candidate for isolated testing and a controlled pilot.**
Controlled production rollout and rollback rehearsals have been completed.
Each installation still requires its own backup, compatibility checks and pilot.

## Features

- Shared user traffic and quotas across Xray and Hysteria2.
- Per-node traffic allowances, scheduled resets and warning/stop-access modes.
- Durable Hy2 journals, retry-safe accounting, drained sessions before resets.
- Unified console, user tags and all-node or selected-node access.
- Filtered hourly reports, CSV, node monitoring/history and incident workflow.
- SSH deployment wizard with preflight, fingerprint checks and rollback.
- Rime identity on login, dashboard, infrastructure, subscription pages and icons.
- Existing subscription routes and user identities retained.

## Run

Use Linux/Docker. Copy `.env.example` to `.env` and configure an isolated data
location before running `docker compose build` and `docker compose up -d`.
The Compose file preserves the upstream `/var/lib/marzban` mount for migration
compatibility; change its host side to an empty test directory for a fresh lab.
Never start a test instance over production data.

The launcher retains upstream TLS/loopback behavior. Configure HTTPS for public
access. Create an admin with `marzban-cli admin create --sudo` (compatibility name).

| Area | Path |
|---|---|
| Unified console: users, reports, monitoring, nodes | `/fleet` |
| Compatibility redirect to Users | `/dashboard/` |
| API docs, if enabled | `/docs` |

The console uses one login session and requires a sudo admin. Set `RIME_FLEET_CONFIG` to
a private JSON file for Hy2 and provisioning; `HY2_PANEL_CONFIG` remains an alias.

Read [console workflow](docs/CONSOLE.md), [operations/migration](docs/OPERATIONS.md), [node quotas](docs/NODE_QUOTAS.md), [testing](docs/TESTING.md),
[brand guidelines](docs/brand/README.md), and [attribution](NOTICE.md).

## Limits

SQLite and one controller process only. New nodes require Docker and supplied TLS
certificates. No ACME, MySQL or multiworker mode. Quotas are polled and can
overshoot. Hy2 accounts accepted payload rather than confirmed delivery.
New Hy2 links support v2ray/link-list subscriptions, not every client format.

Keep existing domains, subscription paths, signing keys, dates, UUIDs, ports and
site-specific subscription additions. Restarting cores can reconnect clients.
Restore panel and node journals from a consistent checkpoint.

## Development

Use feature branches and PRs against this fork. `Rime checks` builds the UI and
runs accounting/operations tests. Upstream release workflows are gated to the
upstream repository; no automatic deployment or image publication is configured.
`core-patches/` targets Hysteria app/v2.12.3. Keep core and agent versions together.
Private credentials, configs, backups and deployment inventories are excluded.

## Credits

Built on [Marzban](https://github.com/Gozargah/Marzban),
[Xray](https://github.com/XTLS/Xray-core) and
[Hysteria](https://github.com/apernet/hysteria).
The AGPL-3.0 [LICENSE](LICENSE), notices and upstream history are retained.
Rime Input Method Engine is an unrelated existing project.

Original [upstream documentation](docs/upstream/README.md) and translated guides
are historical; their installation commands install Marzban, not Rime.
