# Rime interface gallery

These are browser captures of the current `hy2bridge/web` interface. The API
responses come from `scripts/docs_demo.py`, a loopback-only fixture
server. Every account, domain, limit, connection count and metric is synthetic.
No production database, environment file, private key or subscription is loaded.
The example domains and addresses use reserved documentation ranges and cannot be
real VPN endpoints.

## Sign-in

![Sign-in screen](screenshots/login.png)

## Overview

![Network overview](screenshots/overview.png)

## Users, groups and access

![Users and tags](screenshots/users.png)

![User editor with per-node access](screenshots/user-dialog.png)

## Resource monitoring

![Fleet availability, CPU, RAM and disk](screenshots/monitoring.png)

## Traffic reports

![Hourly traffic by protocol, node and group](screenshots/traffic.png)

## Nodes

![Node inventory](screenshots/nodes.png)

## Incidents

![Incident list](screenshots/events.png)

## Explicit tunnels

![Shared entry, per-service checks and transport accounting](screenshots/relays.png)

## Release updates

![Version and release notes](screenshots/updates.png)

![Backup, installation and verification progress](screenshots/update-progress.png)

## Built-in documentation

![Administrator guides and FAQ](screenshots/docs.png)

## Phone layout

![Overview, users and monitoring on a phone](screenshots/mobile.png)

## Reproduce

```sh
python scripts/docs_demo.py --port 18808
```

Open `http://127.0.0.1:18808/fleet`. The demo login accepts `demo` / `demo` (or any
nonempty values); it creates no real session or account. Demonstration actions
change only in-memory fixtures; restart the helper to reset them. The helper does
not start VPN services or make outbound requests. Stop it with Ctrl+C after
capturing. The fixture is for UI examples, not a deployable panel or evidence of
live network performance.

Desktop captures use a 1440×960 browser viewport (the sign-in screen 1440×900).
The traffic capture scrolls to the hourly chart. The update captures open the
version button, choose **Проверить GitHub** and then start the demonstration update.
The phone image combines 390×844 captures at device scale factor 2.

Keep the demonstration label or the surrounding gallery caption. Check each output
before publication for real domains, usernames, tokens, IP addresses and
workstation paths, and strip image metadata.
