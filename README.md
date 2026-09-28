# Rime

**VPN infrastructure management for VLESS and Hysteria2.**

[English](README.md) · [Русский](README-ru.md)

Manage users, subscriptions, traffic and server resources in one console.
Rime brings node access policies, quotas, incident handling and SSH deployment
into the same workspace while preserving existing subscription identities.

![Rime overview with synthetic demonstration data](docs/screenshots/overview.png)

*Actual Rime interface with synthetic data. No production users, addresses,
subscription credentials or server configurations appear in these screenshots.*

## One console

| Users and access | Fleet resources |
|---|---|
| [![Users, tags and quotas](docs/screenshots/users.png)](docs/screenshots/users.png) | [![CPU, RAM and disk across the fleet](docs/screenshots/monitoring.png)](docs/screenshots/monitoring.png) |
| Traffic reports | Nodes |
| [![Traffic by protocol, node and user group](docs/screenshots/traffic.png)](docs/screenshots/traffic.png) | [![Node inventory](docs/screenshots/nodes.png)](docs/screenshots/nodes.png) |

[View the screenshot gallery and reproduction steps](docs/SCREENSHOTS.md).

- **Users:** create and edit accounts, group them with tags, set limits and choose
  all nodes or a specific set. Previously issued subscription URLs remain valid.
- **Traffic:** shared Xray/Hy2 reports, hourly history, user/tag/node filters and CSV.
- **Monitoring:** CPU, memory, disk, availability history and protocol-specific
  connection details, with the panel host shown separately.
- **Operations:** node quotas, incident acknowledgement and diagnostics, controlled
  SSH deployment, and removal with a precise preview of affected panel data.

## Run an isolated instance

Rime **0.2.0-rc6** is a release candidate. Controlled rollout and rollback
rehearsals have passed; qualify your own installation before switching traffic.
Use Linux, Docker Compose, SQLite and one panel process.

```sh
cp .env.example .env
# Configure .env and an empty host-side data directory in docker-compose.yml.
docker compose build
docker compose up -d
docker compose exec rime python rime-cli.py admin create --sudo
```

The default host mount `/var/lib/marzban` is retained for migration compatibility.
Change its host side to an empty directory for a new test instance. Configure
HTTPS before public access. The existing TLS/loopback behavior is preserved.

Open **`/fleet`**. Existing `/dashboard/` links redirect to the Users page;
there is no second dashboard or frontend build. The console requires a sudo
administrator. API permissions and existing subscription routes are unchanged.

Set `RIME_FLEET_CONFIG` to a private configuration file for agents and provisioning.
`HY2_PANEL_CONFIG` and the old CLI entry point remain compatibility aliases.

## Documentation

- [Console and user access](docs/CONSOLE.md)
- [Operations and migration](docs/OPERATIONS.md)
- [Node quotas](docs/NODE_QUOTAS.md) and [node lifecycle](docs/NODE_LIFECYCLE.md)
- [Resource observers](docs/RESOURCE_OBSERVERS.md) and [traffic semantics](docs/TRAFFIC_AND_CONNECTIONS.md)
- [CLI](cli/README.md), [testing](docs/TESTING.md) and [contributing](CONTRIBUTING.md)

## Current limits

No MySQL or multiple controller workers. Provisioning needs an allowed SSH target,
Docker, configured templates/bundles and supplied TLS certificates; it does not
purchase servers or issue certificates. Legacy Hy2 observers provide monitoring
and metering; safe resets and enforcement require the corresponding agent/core
capabilities. Polling quotas can overshoot. Historical data cannot be reconstructed.
New Hy2 links support link-list subscriptions, not every client format.

Keep domains, ports, signing material, UUIDs and consistent backups when migrating.
Node deletion in the panel does not erase a remote VPS, DNS or backup archives.

## Project and attribution

Rime is based on [Marzban 0.8.4](https://github.com/Gozargah/Marzban),
[Xray](https://github.com/XTLS/Xray-core) and [Hysteria](https://github.com/apernet/hysteria).
The original [AGPL-3.0 license](LICENSE), notices and history are preserved.
See [attribution](NOTICE.md) and [upstream provenance](docs/upstream/README.md).
Compatibility names are documented; they are not a separate UI or endorsement.
Rime Input Method Engine is an unrelated project.
