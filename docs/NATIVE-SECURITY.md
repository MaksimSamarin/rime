# Native management identity and source restrictions

Rime identifies a physical native node by its database identity and registration
generation. Entry addresses are transport endpoints, not new trust identities.
The same saved server certificate is used for REST, RPyC, Xray gRPC and log
WebSockets, including control forwarded through an entry.

## Enrolling a certificate

The managed deployment wizard receives the node's management certificate over
the already verified SSH connection and stores it before connecting a controller.
Existing managed nodes can seed their durable pin from the encrypted recovery
profile's management certificate. Reconnecting or changing an entry cannot
replace that pin with a certificate fetched from the network.
Only a verified public-certificate fallback can seed a pin; an old unverified
network cache cannot. Trust material is canonicalized to one certificate so a
supplied PEM chain cannot broaden the subsequent configuration/API handshake.

For manual `POST /api/node` registration, supply the independently verified PEM
certificate in `expected_server_certificate`. A missing value returns a clear
confirmation error before a node is created or a configuration is transmitted.
An existing manual node without a saved pin can enroll its verified certificate
with the same field in `PUT /api/node/{id}`. Obtain the certificate through a
trusted SSH connection or a previously verified backup; copying whatever an
untrusted entry currently presents does not establish its identity.

A changed certificate causes a failed connection and a specific security event.
The old pin remains stored. A successful connection to the original pinned
identity resolves that event. Deleted and recreated node IDs cannot inherit the
former registration's pin. Keep the saved management key and certificate when
moving an existing node. If an authorized transfer needs a new management
identity, the pinned SSH destination must return its certificate before cutover.
The new pin and registration are committed together and journalled for recovery.
A failed or interrupted transfer restores the exact previous pin; a stale
rollback cannot overwrite a newer registration. Rime does not silently rotate
identity during an ordinary connection attempt.

The controller reuses a healthy API transport while its physical endpoint,
pinned certificate and client credentials stay the same. Readiness includes a
real GetSysStats call. If a core crash leaves that transport stale, the controller
retires it and makes one fresh connection; a failed fresh probe fails the
operation. It does not disconnect the control session or stop the healthy core
as a transport-repair shortcut. Qualified restart jobs then reconcile current
database users, preserving changes committed while the core was restarting.

## Source allowlist and independent delivery

Set `provision.control_source` to the panel's actual IPv4. New native installations
restrict both management publications to that address and the selected or
prepared entry IPv4 addresses. Qualified management still requires the panel's
client certificate. Its Xray API listens on an owned private Unix socket behind
the authenticated gateway. Qualified Xray 26.6.1 runtimes use a direct API Unix listener,
with no API_INBOUND or routable API outbound handler for public balancers to
select. The gateway limits concurrent connections both
globally and per source, and checks its local source policy before a handshake.

The panel sends desired source policies in the existing native resource
observer's verified HTTPS telemetry response. The observer writes an atomic
data file in `/control-policy`. A fixed host worker, installed outside the
container's writable state, updates the exact owned DOCKER-USER chain and records
an acknowledgement after the firewall transaction succeeds. The observer sends
that acknowledgement on its next request. Port changes never affect ordinary
VPN or proxy publications.

This channel is independent of the selected inbound controller connection.
It can authorize a replacement entry even if the previous entry is dead. Route
checks wait for the exact current policy revision and digest before probing
and publishing it. A missing observer acknowledgement fails that preparation
while preserving the published route. A runtime without the source-policy
capability is rejected before a new management source is opened.

Active routes, preparation leases and old entries retained for a grace period
or pending owned cleanup remain represented in the policy. Rollback and cleanup
recompute it and revoke unused preparation sources. Observer delivery retries a
deferred refresh without rolling back an already committed route.

The observer shares only a narrow writable policy-data directory. Privileged
host scripts, their configuration and systemd units are outside that mount.
New legacy-runtime installations use the same host-only firewall worker with
their previous source-IP restriction. Cleanup of an older writable-state hook
removes its validated owned chain without executing the old hook.

## Legacy nodes before a runtime upgrade

A legacy Xray API on port 62051 may authenticate the server without requiring a client
certificate. Its external source-IP firewall remains necessary, but it does not
protect loopback traffic originating inside the node container. The forced
private-destination routing protection in the panel-generated Xray configuration
must also be applied to that node. Before sending to a legacy runtime, public
balancer prefixes are restricted to explicit public outbound tags, and public
API routing, proxy-chain and dialer references are rejected. A rejected
configuration is not transmitted and does not stop the existing core.
The hub's local API uses a private Unix socket.
Enabling management forwarding requires the qualified runtime and the independent
source-policy observer channel; a reachable VPN listener is insufficient.

Existing running production nodes are not changed merely by preparing these
source files. Applying protected routing or replacing their runtime remains an
explicit deployment operation. Preserve user UUIDs, signed subscription URLs and
the recovery profile throughout that operation.

See [TUNNELS.md](TUNNELS.md) and [TESTING.md](TESTING.md) for route checks and
closed-environment acceptance. Certificate pinning and source restrictions are
separate from the user accounting and downgrade safeguards.
