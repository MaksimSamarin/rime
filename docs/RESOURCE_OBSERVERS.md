# Resource observers

Existing VPN nodes can report OS resources without replacing their VPN service.
The standalone `hy2bridge/observer.py` runs on Linux with Python 3.8 or newer and
uses only the standard library. It reads CPU deltas, memory, filesystem capacity,
uptime, VPN process state and listening sockets. TCP connections are transport
connections, not a count of authenticated users. Hy2 connection counts are not
estimated from UDP sockets.

Configure distinct, randomly generated tokens of at least 32 characters in the
panel fleet configuration's `observers` list. Each entry has `node`, `kind`,
`token`, `name`, `address`, `domain` and `port`. `kind=native` references an existing
`xray:<id>`; `kind=legacy_hy2` creates a monitoring-only inventory card without
adding or changing any subscription endpoint. The panel stores token hashes.
Removing an entry and restarting the panel revokes its telemetry credential.

The node configuration contains `url` (verified HTTPS ending in
`/api/fleet/telemetry/<node>`), `token`, `protocol` (`xray` or `hysteria2`),
`vpn_port`, `process_names`, optional `disk_path`, `core_version` and `interval`.
Protect it with filesystem permissions; credentials must not be logged.
The observer rejects redirects and bypasses environment proxies.

Run `python3 observer.py --config /etc/rime-observer/config.json`. `--once` sends
one sample; the second sample is needed to calculate CPU usage. A service should
run with no write access to VPN configuration, no capabilities, a memory/CPU
budget and restart-on-failure. It never starts, stops or modifies the VPN core.

Telemetry tokens authorize only resource updates for their own node. They do not
authorize user APIs, accounting, policy changes, quota resets, traffic-check
acknowledgements or barrier acknowledgements. Resource reports do not establish
that VPN payload passes end to end. That requires an independently configured
traffic probe; the UI labels the difference.

Legacy Hy2 cards expose resources and service state; only their display names
are editable. VPN settings, user-node restrictions and node quotas remain
unavailable until control/accounting migration. Existing subscription additions
must remain intact during this monitoring step.

Resource samples older than 30 seconds do not contribute CPU/RAM/disk totals.
A missing native resource sample does not override independently confirmed
Xray connectivity. Historical recovery inside a time bucket is shown separately
from a currently failing final sample; missing history remains unknown.
