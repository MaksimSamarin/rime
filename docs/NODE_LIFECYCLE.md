# Adding and removing nodes

## Add a supported Linux node

The operator supplies the server address, SSH port/account, password or private
key, verified SSH host-key fingerprint, VPN protocol/port, connection domain and
matching TLS certificate/private key. The domain must resolve to the server.
Docker and Python 3 must be available to that SSH account. Panel provisioning
configuration must permit the host and provide a public HTTPS panel URL, pinned
runtime images, the VLESS inbound template and/or qualified Hy2 core/agent bundle.
An optional panel CA file supports a privately issued panel certificate.

The normal wizard checks access, ownership, free ports and disk capacity. It
creates only its own labelled container and directory. Managed Hy2 sends resource
telemetry through its agent. VLESS receives a separate small resource-observer
container automatically, with a scoped credential, shared VPN process/network
namespace and explicit host `/proc` resource binds to preserve LXC virtualization.

A running VPN container is not sufficient for success. The panel waits for a
fresh CPU sample, RAM/disk totals and available values, interface counters,
connection count and healthy service state before publishing the new endpoint.
Missing/stale metrics cause a failed setup with an explicit reason and rollback
of only the newly created registration/containers. Diagnostic files remain.
Repeated identical observer setup reuses its owned container. Different existing
configuration is rejected; a repeated add attempt on occupied ports does not
create duplicate nodes. No VPS is purchased or created by the wizard.

## Remove from the active panel

Use the node's **Delete from panel** action. The preview names the exact node and
address, enumerates subscription addresses, affected user-node associations,
records to delete and retained data. Confirm by typing the exact displayed name
and acknowledging the scope. A changed identity/configuration requires a new
preview. The panel server cannot delete itself through this action.

Deletion removes this node's registration, scoped credential hashes, host links,
managed/external subscription endpoints, meter/health/traffic history, events,
event actions, checks, quotas, associated completed provisioning job and runtime
caches. User records, UUIDs, limits, expiry, tags and global used-traffic totals
are preserved. Removing the last explicitly selected node leaves an empty access
set; it must never silently grant access to all other nodes. Shared inbound
definitions, panel TLS material and other nodes remain intact.

Native Xray is disconnected from the panel and its active connections stop.
Removing a legacy Hy2 entry removes it from newly fetched subscriptions, but its
external service can still accept previously saved profiles until separately
decommissioned. Do not infer remote erasure from panel deletion.

Remote cleanup is a separate action requiring the correct host/SSH access and
ownership verification. Managed deployment containers are named `fleet-<job>`
and `fleet-observer-<job>`; only matching `fleet.job` labels and their own
`~/.local/share/fleet-nodes/<job>` directory may be targeted. Existing standalone
observers use `rime-observer.service`, `/opt/rime-observer` and
`/etc/rime-observer`; verify their configured node identity before cleanup.
Do not remove another service, shared certificate, proxy, user directory or disk.
If the host is unreachable, panel deletion may proceed only with explicit
acknowledgement that remote files/services remain and need later cleanup.

Existing backups, rollback deployment bundles, external logs, DNS and provider
instances are not erased. The feature performs logical active-data cleanup, not
forensic erasure of storage or copies outside the live panel. Restoring an older
backup can restore deleted data. Retention/purge of those copies is a separate
operator decision; no absolute erasure guarantee is made.
