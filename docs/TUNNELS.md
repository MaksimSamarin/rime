# Entry servers and tunnelled nodes

The development console can publish an existing exit node through a selected
entry server. One entry serves several exits. VPN keys and signed subscription
URLs remain attached to the existing users and node identities.

## Development setup

Enable `provision.relay_enabled` in the private fleet configuration of the review
environment. The image includes the checksum-qualified GOST runtime. Entries
require Linux amd64, Python 3, systemd and root SSH access for installation.

Create the entry's DNS record yourself before checking the server. The installer
uses the pinned direct SSH endpoint shown in its plan. It installs an owned
low-privilege forwarding service and a separate resource/accounting observer.
Existing VPN and proxy services keep their ports.

## Connecting an exit

Open **Tunnels → Connect node**, or **Tunnelling** in the node card.
Select an existing node and an entry. The exit IP is stored independently of its
public client hostname. This prevents forwarding loops when DNS is changed.

The plan includes saved VPN listeners and optionally the node's registered
HTTP/HTTPS proxies. It allocates public ports separately for TCP and UDP and
reserves ports already used by the entry. A shared entry may assign a different
public port when a listener is occupied.

The bind itself is checked during installation. If another service has occupied
a newly allocated port, the job selects another free port and records the final
mapping. Previously published ports are preserved during proxy replacements.

Review the complete entry-to-exit port map before installation. Client payload
checks must pass before the route is published in subscriptions. Refresh the same
subscription in each client to receive the entry endpoint. Existing cached
individual configurations still contain their previous endpoint until refreshed
or updated through DNS with a matching port map.

Forwarding preserves the exit VPN/TLS/proxy authentication. VPN configurations
keep their original TLS SNI. HTTPS proxies require the existing certificate to
cover the entry hostname. The installer checks this before enabling the route.

Native VLESS management can explicitly use the same entry. Include both native
control and Xray API services in the plan: a reachable VPN listener alone does
not make the node manageable. Optional SSH forwarding appears as a named route
in proxy operations. A forwarded SSH connection is checked against the exit
server's host-key fingerprint.

## Managing VLESS through an entry

With management forwarding enabled, the existing panel controls use the selected
entry to reach the same physical exit. Creating a user, changing a UUID,
enabling, disabling or deleting access, applying quota and expiry decisions,
collecting usage and reading live logs all use this path. User identities,
signed subscription URLs and protocol settings remain attached to the exit.
Changing the entry does not change the exit's VPN keys or require a new user.

This requires the qualified native runtime shipped with this release, for both
REST and RPyC nodes. Upgrade older node runtimes before enabling management
forwarding or switching their management path. The panel checks the runtime's
authenticated-API capability and both management services before publication;
an older runtime or an unreachable control/API service is rejected while the
current published route is retained.

Both public management services require the panel's client certificate. The
Xray API itself listens on a private Unix socket behind that authenticated
gateway; it is not exposed as an unauthenticated loopback TCP service. Ordinary
VPN users cannot obtain management access by requesting the exit's local API.
Forwarding does not terminate or replace these authentication checks.

The panel keeps protocol options and controller locks keyed to the physical
exit while replacing the effective entry endpoint. Taking over an already
running qualified core preserves its process, users and counter epoch.
Reconnecting the panel does not send a stop command to that core. A connection
through a failed entry still needs to reconnect through the replacement entry.

## Availability and accounting

The selected-path probe checks actual VPN and proxy payload through the entry.
Direct availability from the panel remains a separate observation. A running
service or resource heartbeat alone does not establish client availability.

While a route is active, clients receive the entry address, so the node's
state and monitoring history follow the selected-path probe, which runs every
minute. A failed or blocked direct address does not raise
`client_unreachable` for such a node and resolves an open one. The direct
result stays visible in the node card. A failed path through the entry
degrades the node and opens `relay_client_unreachable`. After the route is
removed, direct probes raise incidents again.

Entry transport counters are separate from VPN user balances. They include
protocol overhead and show what passed through each forwarding service. User
limits continue to be charged once by the exit. Management and SSH forwarding
have distinct service kinds.

Qualified native nodes expose a core counter epoch. The panel reads cumulative
user and outbound counters without resetting them and commits each accepted
counter position together with its usage changes. A lost reply, an idle poll or
a retry after a rolled-back database transaction cannot charge the same sample
twice. The physical-exit lock also serializes collection with controller
replacement and user changes. Entry switches retain that exit's epoch and
accounting position; transport overhead is not added to user balances.

If the panel is temporarily unavailable while the same exit core keeps running,
its next cumulative read can collect the intervening traffic. A core restart
starts a new epoch; traffic not sampled before an abrupt core failure cannot be
recovered from memory. Older runtimes and local APIs without this capability
keep their existing reset-based collection. This qualification does not cover
manual counter resets racing with collection or a cold exit start while the
panel is unavailable.

VPN payload, proxy payload and SSH reachability have separate results. A failed
proxy check leaves a successfully checked VPN path available. The monitoring
view labels configuration failures and stale checks explicitly. **Check route**
repeats the selected-path probes and can restore missing owned forwarding rules.
Recovered probes close the corresponding incident automatically.

## Editing an existing route's services

Proxy creation on a tunnelled exit adds its forwarding rules automatically when
the route includes proxies. Proxy replacements preserve existing public entry
ports while the exit's local ports or credentials change. Copy actions return the
currently published endpoint and saved credentials.

The SSH form identifies a selected administrative forwarding route. Source
credentials are checked against the exit's SSH key. The stored physical origin
also protects administration when the public hostname points at the entry.

The node-transfer wizard retargets its selected entry rules after checking the
replacement exit. Public entry ports and user access remain attached to the
same node. Failed changes restore the previous route. Interrupted changes have
a durable before/after journal and are reconciled when the panel returns.

## Changing the entry server

Choose **Change entry** on an existing tunnel, select another prepared entry and
review its port map. Planned switches keep the former entry's rules for 24 hours
by default; the dialog offers 24, 48 or 72 hours, or immediate cleanup. The private
`relay_switch_grace_seconds` setting supplies the API default, from 0 to 259200.
The current entry may be unreachable; an emergency switch skips that grace
period and retains only deferred cleanup. The panel prepares
the new forwarding rules and checks VPN and any included HTTP/HTTPS proxies
before publishing the new entry for that node. Each selected entry must reach
the physical exit and its HTTPS hostname must match the saved certificate.
When native management is selected, the checks also authenticate both control
services and query the real Xray API through the proposed entry. A working VPN
with a blocked management listener is insufficient to commit the change.

The same node identity, user keys and signed subscription URL are retained.
Refresh that subscription in clients to receive the new endpoint. Existing
connections may reconnect, and occupied listener ports may lead to a new public
port shown in the plan. Entry changes are initiated by the administrator.

The progress bar follows the server's completed stages and reaches completion
after the job has finished. Reopening the page restores the current job. A failed
new-path check retains the previously published route. Once the new path is
committed, an unreachable previous entry leaves a visible cleanup note. The
panel retries removal of that route's owned rules when the former entry returns.
Other exits using either entry keep their forwarding rules.

**Return to direct address** withdraws the selected route's publication even
when its entry cannot be reached. The same subscription then contains the saved
direct endpoints; refresh it in clients. The confirmation identifies the chosen
node and explains that direct reachability must still be checked. Exact owned
rules are journaled for removal when the old entry returns. This operation keeps
the exit's VPN/proxy services, keys and historical transport ownership.

Explicit direct withdrawal also abandons interrupted durable route changes and
switches after a controller restart. An orphaned database job still marked
running does not trap the node on the dead entry. Actual in-memory entry/exit
operations remain protected: wait for those workers to finish. Abandoned
journals cannot later restore their old publication. Their known before/after
rules join deferred ownership-checked cleanup; physical node or proxy recovery
may still need a separate explicit check through the direct path.

If the entry will never return, **Forget entry** requires its exact domain as
confirmation after all current routes have been withdrawn or moved. It revokes
the stored entry credential and explicitly abandons pending owned cleanup.
Remote services are not contacted or erased. Remove them separately if that
server later becomes accessible. An entry with active routes or unfinished
configuration changes cannot be forgotten.

Transport history stays associated with its original entry and service
generation. Delayed observations from the previous entry are still accepted,
and the current route displays its accumulated traffic across the switch.

For an IP-only change, edit the exit address in the node card. A routed
Hysteria2 node has a separate physical exit IPv4 field alongside its public
hostname. The panel checks the new path before accepting the endpoint change.

The local observer receives cumulative forwarding statistics over a loopback-only
HTTP endpoint requiring a separate local bearer token stored in the entry's
private configuration files. GOST supplies that token; the panel-delivery token
does not grant local observation access. The observer journals process and
service generations independently. Retired
connections keep their original generation after a hot replacement. Prometheus
export is disabled to avoid retaining a label series for every former service.
Repeated delivery is idempotent. Its bounded local backlog covers up to six days
and coalesces older samples while preserving counter generations. Central hourly
transport history retains 90 days. Gaps after a longer outage cannot recover
hour-by-hour timing. An abrupt forwarding-process failure can lose its last
unreported sample. Transport observations do not replace user quota accounting.

Health has a separate receipt stream and retains its newest queued snapshot,
so old rejected traffic cannot prevent fresh resource reporting. Permanent
per-packet 400/409/422 rejections enter a bounded private quarantine (up to 256
packets and six days). Rejected mixed-service batches are retried as individual
service samples so an unknown service does not suppress known counters. The
entry card displays the quarantine count. Authentication failures, rate limits,
server errors and transport failures keep their normal retry behavior.

Forwarding runs from local configuration when the panel is unavailable. The
observer's delivery failure leaves the forwarding service running. Losing the
entry itself interrupts every route using it. Each entry must also reach its
selected exits.

## Removing services

Removing a route withdraws only that exit's forwarding rules and returns the
same subscription to direct endpoints. Other routes on the entry continue.

Deleting a registered proxy stops its actual owned installation, removes its
selected forwarding rules and removes it from the node's recovery profile.
The deletion dialog shows the affected ports and waits for the removal check.
Forwarding withdrawal is recorded in the same durable change journal used by
other proxy changes. Recovery restores the original rules after an interruption
before publication, or retains the committed removal. Deleting a direct-only
proxy does not require access to an unrelated tunnel entry. Interrupted cleanup
can be retried. Keep current SSH access to the exit, either
directly or through its explicitly selected SSH route.

The relay implementation is prepared for development review. Use the closed
systemd qualification in `tests/relay_integration.py` and the native management
qualification in `tests/relay_management_integration.py` before enabling it on a
production installation. See [TESTING.md](TESTING.md) for the acceptance criteria.
