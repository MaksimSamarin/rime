# Rime 0.2.0-rc3

Node monitoring now reads the native node rows completely before making network
calls. An unfinished SQLite cursor in rollback journal mode previously retained
a read lock throughout remote RPC calls. Concurrent accounting could fail with
`database is locked` when a remote check took longer than the database timeout.

A regression test performs an independent accounting commit during each native
node probe. It reproduces the lock on RC2 and succeeds with RC3. No journal-mode,
subscription, identity, quota or node configuration changes are required.

This fixes the monitoring lock; it does not make native Xray reset counters
durable against unrelated failures. Bytes from an already failed reset-based
accounting cycle cannot be reconstructed exactly from the stored user totals.

The RC2 panel-first migration constraints continue to apply. Hy2 agents and
Rime-only policies require separate qualification before activation.
