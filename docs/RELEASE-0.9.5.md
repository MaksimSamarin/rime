# Rime 0.9.5

Rime 0.9.5 lets the update dialog stop an update and roll back to the previous
version, judges tunnelled nodes by the path clients actually use, and makes the
subscription switch in the node card a visible button.

## Updates

- **Stop update.** While a release is queued, checked or downloading, the dialog
  offers **Stop update**. The host worker ends the job before the backup and
  leaves the panel untouched. After the backup has started, the existing
  automatic restore protects a failed installation.
- **Roll back to the previous version.** After a successful update the worker
  publishes the version it replaced when a rollback would be accepted. The dialog
  offers it with a confirmation. The current database is kept, the schema must
  match, and a failed readiness check returns the current version. After a
  rollback the dialog offers to return.

## Monitoring

- **Tunnelled nodes.** While a route through an entry server is active, the node
  state and monitoring history follow the per-minute check through the entry. A
  blocked direct address no longer keeps a permanent `client_unreachable`
  incident; the direct result stays visible in the node card. A failing path
  through the entry still degrades the node.

## Console

- **Node in subscriptions.** "Remove from all subscriptions" and "Return to
  subscriptions" are now visible buttons instead of text-styled links.

## Compatibility

No database migration. Existing users, subscriptions and node registrations are
unchanged. Stop and rollback need the host worker from 0.9.5: run
`scripts/install_updater.py` from the 0.9.5 source once, then update with the
version button; see [UPDATES.md](UPDATES.md). The rollback offer appears after
the first update performed by that worker.
