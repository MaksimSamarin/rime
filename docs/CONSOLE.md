# Unified console

Open `/fleet`. `/dashboard/` and its nested paths redirect to the Users page in the same console. Navigation uses one authenticated session. The console currently requires a sudo administrator; native API permissions are unchanged.

| Page | Purpose |
| --- | --- |
| Users | Search, create and edit users; limits, expiry, status, notes, tags and subscription links |
| Traffic | Shared report by period, protocol, node, current user tag and searchable user selection; CSV uses the same filters |
| Monitoring | All nodes in one view: CPU, used/total/free RAM and disk, status, resource pressure, sample age, search and sorting; fleet totals and seven-day availability history |
| Nodes | Open a node to inspect its settings, resource history, traffic and incidents; rename it and associate subscription hosts |
| Events | Investigate a fault, read recovery guidance, record an administrator comment and acknowledge work |

Exit-node cards include **Node traffic limit**: amount, direction, daily/weekly/monthly
or manual periods, next reset date and warning-only/stop-access behavior. The fleet
table displays usage and remaining quota. See [node quota accounting and enforcement](NODE_QUOTAS.md).

## User access

Existing users default to **All nodes**, including future nodes. A selected-node user receives access only to the listed nodes. Metadata is tied to both the database user ID and creation timestamp, so reusing an ID does not transfer another user's tags or restrictions.

Hy2 policy and managed Hy2 links respect the selection. Xray applies it during live user updates, local core startup and remote node startup/reconnect. Existing Xray sessions may remain until disconnected: removing an account does not guarantee immediate termination of every existing transport session.

Native subscription formats share the host filter. Managed VLESS hosts are associated by their recorded native node ID. Exact, unique matches of legacy node addresses and local `{SERVER_IP}` / `{SERVER_IPV6}` hosts are associated automatically. For aliases or ambiguous hosts, select the corresponding subscription addresses in the node settings. Unmapped hosts are omitted for restricted users. **All nodes** preserves the existing host list. Credentials and signing keys are not reissued; previously issued subscription URLs remain valid.

Tags are groups for search and reporting, not authorization roles. A tag report uses current group membership and retained traffic belonging to the same user identity. Changing a tag changes the group report, not recorded counters.

## Incident workflow

- **New**: a current fault requires investigation.
- **In progress**: an administrator has acknowledged it and can leave a comment. This does not suppress the fault or mark the server healthy.
- **Recovered**: telemetry or the native connection confirms recovery. Acknowledgement of a Hy2 outage is retained when its recovery event is recorded.

Repeated reports of one active error increase its confirmation count. They are not separate outages. Recovery checks do not restart remote services or execute arbitrary repair commands. Deployment failures include diagnostic guidance and remain visible for investigation; rollback is reported separately.

## Monitoring limits

History is collected every minute and retained for seven days. It starts when this version starts; missing intervals are not reported as uptime. Load average is not CPU utilization percent. Available RAM and disk refer to the operating system visible to the reporting process, not a container quota.

Resource charts label their lower, middle and upper scale bounds and UTC time
endpoints. CPU utilization uses 0–100%; RAM/data-disk use the known capacity
(including larger historical capacities), otherwise a rounded observed range.
Load and connection counts use a rounded non-negative range. Last/minimum/maximum
observations are listed separately from axis bounds; missing intervals stay gaps.

Hy2 metrics depend on agent heartbeats. Existing native Xray nodes expose connection state and core version; resource/session metrics remain unavailable until their agent supplies them. The local core also reports OS memory, disk and load. Stale samples are historical observations, not current measurements.

The fleet resource summary includes only samples no older than 30 seconds and shows
coverage separately for CPU, RAM and disk. CPU is the highest measured utilization
among nodes, not a sum of percentages. RAM and disk totals sum only complete pairs
of capacity and free space; missing data never becomes zero usage. The local panel
now samples CPU utilization across requests and reports capacity for its data disk.
These are OS-visible resources, not container limits. CPU/RAM warn at 80% and become
critical at 95%; disk thresholds are 80% and 90%. The attention filter also includes
offline nodes, service errors and missing metrics. Sorting and search stay on the
same page during automatic refreshes. A failed refresh keeps the last response
with an error label while its samples age out normally.

The current panel host is pinned above the fleet summary. It shows OS CPU/RAM,
the panel data disk, Rime version, process RSS, process/OS uptime and runtime
hostname. In Docker, the runtime hostname may be a container ID. Panel reachability
and local Xray state are shown separately. It retains `xray:local` for accounting
and access rules, and contributes to fleet totals once. Local resource measurements
remain fresh when Xray stops because the panel still collects them.

Opening `xray:local` shows the management hub view: panel identity, OS resources,
uptime and events. It has no remote-node form, subscription-host selector or
unsupported VPN-probe button. Existing local VPN host mappings and usage remain
available in a collapsed read-only section. Hub node edits reject remote-connection,
publication and host-mapping fields before writing anything. Existing subscription
links, mappings and user access are preserved. Remote exit nodes retain their
subscription-host associations and connection settings.

Native VLESS settings update the node address, service/API ports, usage coefficient
and enabled state, then reconnect the node. Managed Hy2 edits change subscription
inventory metadata; remote service reconfiguration requires controlled deployment.
TLS and SSH credentials are not edited by the resource overview.

## Deployment

The console adds `fleet_user_meta`, `fleet_host_nodes`, `fleet_node_labels`, `fleet_event_actions` and `fleet_health_history` to the existing SQLite database. Keep one panel worker. Take a consistent SQLite backup before upgrade. Follow the existing isolated rehearsal and rollback process before a production rollout.

`RIME_DEMO=1` displays the demo banner. It does not create fake metrics or disable provisioning by itself. Isolated demos must use synthetic state, an empty provisioning allowlist, no production credentials and network isolation.
