# Rime 0.9.3

Rime 0.9.3 adds a switch that withholds a node from every subscription and makes
node addresses and tunnelled probe results easier to read.

## Console

- **Node in subscriptions.** The node card can withhold all addresses of a VLESS
  or Hysteria2 node from every subscription and return them later. The change
  applies to the next subscription request without a restart or node reconnect.
  Access on the node itself is not revoked. Hidden nodes are marked in the node list.
- **Addresses of this node.** The list shows each address with its port and inbound,
  marks addresses disabled in subscriptions, and no longer lists addresses that
  belong to other nodes.
- **Tunnelled nodes.** When the direct address of a node behind an entry server
  fails the client probe while the route through the entry works, the event says
  so and is shown as a warning instead of an outage.

## Compatibility

No database migration; the visibility table is created at startup. Existing users,
subscriptions and node registrations are unchanged. Update from 0.9.2 with the
version button; see [UPDATES.md](UPDATES.md).
