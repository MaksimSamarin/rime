# Rime 0.2.0-rc4

Resource-only observers populate CPU, RAM and disk metrics for existing native
nodes and add monitoring cards for legacy Hy2 nodes without changing their
subscriptions or VPN services. Credentials are scoped to one telemetry endpoint;
legacy control and accounting remain separate migration steps.

The availability timeline now distinguishes recovery inside an interval from
an active failure in its final sample. Missing native telemetry no longer labels
an independently connected native core offline.

See [resource observer operations](RESOURCE_OBSERVERS.md) for configuration,
credential scope, service isolation and the distinction between resource checks
and actual VPN payload checks. The RC3 SQLite cursor fix is retained.
