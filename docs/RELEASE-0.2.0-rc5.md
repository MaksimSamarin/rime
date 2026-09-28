# Rime 0.2.0-rc5

Legacy Hy2 metering adds durable delivery of non-destructive core counter reads,
hourly history, interval-average rates and explicit restart/sampling gaps.
Protocol-specific connection details distinguish native TCP transports from
Hy2 client instances and authenticated IDs without publishing credentials or
traffic destinations.

Provisioning now deploys VLESS resource observers automatically and requires
complete fresh metrics before reporting success for either supported protocol.
Node deletion adds an exact preview and confirmation, scoped active-data cleanup,
subscription removal and protection of other nodes/shared user records. Remote
host cleanup, provider deletion and backup erasure remain separate operations.

See [traffic semantics](TRAFFIC_AND_CONNECTIONS.md) and
[node lifecycle](NODE_LIFECYCLE.md) for precise scopes and prerequisites.
