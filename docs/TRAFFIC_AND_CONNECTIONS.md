# Traffic and connection metrics

## Different counters

- VLESS observer connections are current TCP sockets in ESTABLISHED state whose
  local port is the configured VPN listener. SSH, control/API ports, listening
  sockets, TIME_WAIT and unrelated outbound connections are excluded. XHTTP can
  use several transports for one client. This does not identify authenticated
  users or physical devices.
- Hysteria `/online` counts connected client instances per authentication ID.
  Multiple proxied streams of one instance do not increase that instance count.
  `online_users` counts IDs with at least one connection, not people.
- Connection details expose counts and stable HMAC pseudonyms for IP sources or
  authentication groups. Raw UUIDs, credentials and traffic destinations are not
  published. Source IP grouping is not user/device identification; NAT can group
  several devices. Full group snapshots are not copied into long-term history.
- OS interface byte counters include other services, control traffic and possibly
  virtual/loopback interfaces. They are not used as VPN billing counters. Squid
  HTTP/HTTPS proxy usage is not an Xray or Hy2 user-traffic statistic.

## Legacy Hy2 metering

Enable authenticated `trafficStats` on loopback only. On existing legacy cores
this requires a controlled restart; preserve all client credentials, address,
VPN port, SNI and obfuscation settings. The new statistics secret is an internal
credential, not a replacement client password.

The optional observer `meter` configuration contains a verified HTTPS delivery
URL `/api/fleet/meters/<node>/usage`, a separate per-node token, a writable durable
spool path and the VPN systemd service name. The panel `meters` entries register
the matching node/token. Resource and metering credentials are independent;
neither authorizes user administration or VPN control.

The collector reads `/traffic` without `clear`, samples a stable process epoch,
and commits cumulative deltas to its SQLite spool before delivery. Panel usage,
hourly history, accepted cursor and meter metadata commit together. Repeated
delivery of an accepted batch does not charge twice. Collector restart preserves
the spool; changing or deleting a spool requires explicit reconciliation.

Directions are from the user's perspective: `tx` is uploaded payload and `rx` is
downloaded payload. They exclude interface/tunnel overhead. Speed is average
bytes per second over the measured interval, not instantaneous bandwidth.

A legacy core restart resets its in-memory counters. The next epoch adds new
bytes to the durable lifetime total, but bytes after the last pre-restart sample
may be unrecoverable. The panel marks this interval as possibly incomplete and
does not calculate a rate across it. A missed poll with the same surviving epoch
can catch up from cumulative counters; it is marked as a sampling delay rather
than assumed data loss. No historical consumption is fabricated before collection.

Charts aggregate by posting hour. Unknown hours have gaps, not invented zeroes;
a confirmed zero sample remains zero. The node shows when panel collection
started and when the current core counters started. Existing user limits remain
unchanged, while actual newly collected bytes increase used traffic. Legacy
node-level enforcement and safe period-reset migration remain separate steps.
