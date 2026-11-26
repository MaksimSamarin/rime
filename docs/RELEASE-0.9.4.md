# Rime 0.9.4

Rime 0.9.4 lets the update worker finish downloads on slow routes to GitHub and
corrects the update dialog when the browser loses contact with the panel.

## Updates

- **Resumable release download.** When the connection to GitHub closes before the
  archive is complete, the host worker continues from the received bytes with an
  HTTP Range request instead of failing with a checksum error. The finished archive
  is verified against the signed manifest exactly as before. A long transfer that
  drops repeatedly still completes as long as each attempt makes progress.
- **Update dialog.** While the release is downloading or being backed up, the panel
  keeps running. A failed status request now says that the update continues on the
  server. The message about waiting for the restart appears only during
  installation and verification. The download line shows how many times the
  transfer was resumed.

## Compatibility

No database migration. Existing users, subscriptions and node registrations are
unchanged. The resumable download lives in the host worker, which panel updates
do not replace. Run `scripts/install_updater.py` from the 0.9.4 source once, then
update with the version button; see [UPDATES.md](UPDATES.md).
