# Rime 0.9.2

Fixes VLESS node setup and transfers on servers that need extra time to
generate their management TLS credentials. The installer waits up to 30 seconds
for a matching certificate and private key before registering the node.

If the container stops or never produces a valid pair, Rime keeps the previous
registration and reports the failure. Certificate pinning still uses the pair
read over the verified SSH connection.

The existing database, user keys and signed subscription URLs are compatible.
Update the panel from the version dialog. [Update instructions](UPDATES.md).
