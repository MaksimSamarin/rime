# Node traffic quotas

Open **Nodes → node → Node traffic limit**. Quotas default to disabled. Configure
the amount (decimal GB/TB), direction, recurrence, next reset date at 00:00 UTC,
and warning-only or stop-access behavior. Warning incidents appear at 80%, 95%
and exhaustion. The fleet monitor shows used / limit / remaining bytes.

The quota ledger counts raw VPN payload, independent of user consumption factors.
Outgoing means payload delivered toward VPN clients; total means upload plus
download. Hysteria statistics use `tx` for client upload and `rx` for client
download ([upstream definition](https://v2.hysteria.network/docs/advanced/Traffic-Stats-API/)).
Native Xray uses its recorded outbound uplink/downlink counters. This is not a
provider invoice or NIC counter: protocol overhead and non-VPN services are not
included. Counter polling permits overrun between samples. Native Xray counters
are volatile and retain the upstream crash/lost-poll limitations.

## Periods and persistence

Accounting starts from a captured baseline on first enable. Editing a limit or
direction does not erase usage. Daily/weekly/monthly boundaries are UTC midnights;
monthly dates clamp to the final day of short months while retaining the original
anchor day. Traffic is assigned by its posting hour. Delayed batches may therefore
land in the following period. Manual **Start new period** advances only this node's
baseline and keeps its scheduled reset date. It does not erase history, reset user
allowances, change UUIDs or reissue subscriptions.

`fleet_node_traffic` retains raw hourly deltas using SQLite triggers on
`hy2_totals` and `node_usages`. Trigger changes commit with their source updates;
Hy2 replay is still idempotent. Historical backfill runs once, not at each startup.
`fleet_node_quotas` holds configuration/baselines and `fleet_quota_audit` records
setting changes and manual/scheduled resets. Deleting a node clears its quota
identity, avoiding inheritance if a numeric ID is reused. Native node recording
must be enabled before a native quota can be enabled.

## Enforcement

Hysteria receives an empty allowed-user policy for the exhausted node and its
existing enforcement loop kicks sessions. The auth/telemetry agent stays running
so a period reset can resume access. Xray restarts only the affected core with
VPN listeners omitted and its administrative API retained, closing old sessions.
Native counters are flushed before the restart. Reconciliation waits for the
management API to recover without repeatedly restarting the core. A disconnected
native node cannot be stopped until its control connection recovers; the UI shows
the pending transition. Startup configuration filtering preserves an exhausted
quota through panel/node restarts. A higher allowance, warning-only mode,
disabling the quota or a new period restores access.

The panel hub view stays focused on management. Its optional local VPN can be
limited via the same node API (`xray:local`); the web panel remains reachable.
Subscription generation is intentionally unaffected by quota blocking. Other
nodes and per-user limits remain independent.

## Qualification

`tests/test_node_quotas.py` verifies direction, replay, edits, resets, monthly
boundaries, warning deduplication and management-API preservation. Run the isolated
network-none `tests/e2e.py` with `NODE_QUOTAS=1` for real Hy2/VLESS payload,
connection closure, node isolation, panel restart and same-subscription recovery.
Never point the lab harness at a production database.
