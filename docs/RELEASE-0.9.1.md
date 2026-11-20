# Rime 0.9.1

Rime 0.9.1 reduces how often the panel and Hysteria2 agents exchange usage and
makes the agent tolerate a slow panel response.

## Panel

- VLESS user usage is collected every 60 seconds instead of 10, and node totals
  every 120 seconds instead of 30. Set `JOB_RECORD_USER_USAGES_INTERVAL` and
  `JOB_RECORD_NODE_USAGES_INTERVAL` to keep the previous values.
- Longer intervals delay usage reports and quota decisions by up to one interval.
  On nodes whose counters reset on read, an abrupt core restart can lose up to one
  interval of unsampled traffic.

## Hysteria2 agent

- The agent waits up to 10 seconds for the panel and the local statistics API
  (`http_timeout` in its configuration) instead of 2 seconds. A briefly slow
  panel no longer appears as an accounting failure.
- New installations run the agent cycle every 5 seconds instead of every second.
  Usage, access rules and heartbeats are exchanged once per cycle. Usage is kept
  in the durable local spool until the panel acknowledges it.

The panel update does not change existing nodes. To apply the agent change to an
existing Hysteria2 node, replace `hy2bridge/node.py` in its state directory, set
`"interval": 5` and `"http_timeout": 10` in `agent.json`, and stop only the agent
process recorded in `hysteria.pid.agent`. The supervisor restarts the agent while
Hysteria keeps serving existing sessions.

## Compatibility

No database migration. Existing users, subscriptions and node registrations are
unchanged. Update from 0.9.0 with the version button; see [UPDATES.md](UPDATES.md).
