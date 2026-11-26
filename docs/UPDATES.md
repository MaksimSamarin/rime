# Updating Rime from the panel

The version button in the sidebar shows the installed version, published release
notes and the progress of the current update. Only sudo administrators can check
or install updates.

Release manifests require an Ed25519 signature from a separately provisioned
signing key. The verification public key is pinned in the panel and host worker.
Checksums from an unsigned manifest on the same download site are insufficient.
Missing, unknown-key and invalid signatures stop the update.

## One-time host setup

The Docker host needs Python 3, systemd and access to its own Docker daemon.
It also needs Python cryptography or OpenSSL 3 for signature verification.
Install the host worker from the same reviewed Rime source used for the panel.

```sh
sudo python3 scripts/install_updater.py
```

Run it from the directory containing `docker-compose.yml`; it finds the running
`rime` service. For a panel started without Compose, pass the existing container
name with `--container <name>`. The panel must set an absolute
`SQLALCHEMY_DATABASE_URL` on a persistent mount, for example
`sqlite:////var/lib/marzban/db.sqlite3`. The installer discovers that SQLite
database and persistent mount, preserves the container settings and creates
`rime-update.path` and `rime-update.service`. The web container receives a narrow
file queue under its data directory. The Docker socket stays on the host. Compose discovery may return a container
ID; the installer resolves the canonical name before saving it. A 64-hex name
is rejected. The installed configuration supports consecutive updates.

The host worker is not replaced by panel updates. To pick up worker changes, such
as the resumable download added in 0.9.4, run the installer again from the new
source with the same container name. It keeps the previous `config.json` and unit
files next to the new ones as `*.before`.

Installations that bind source code over `/code` need an image-based deployment
before the UI updater can replace their code. SQLite and a single panel process
are required. Linux amd64 is the qualified release platform.

## Installing a published version

1. Open the Rime version button and choose **Check for updates**.
2. Review the version and release notes.
3. Choose **Install update**. The host verifies the official repository's release
   manifest, archive checksum, image configuration, platform and OCI labels.
4. Follow downloading, backup, replacement and verification in the dialog.

The worker refuses concurrent updates and waits for provisioning operations to
finish. It creates a coherent SQLite snapshot and a data archive before replacing
the panel container. Mounts, existing environment settings and administrator
credentials are carried forward. A failed readiness check restores the prior
container and saved data. Private-file ownership and symbolic links are restored
without writing through external link targets. The dialog can be closed and
reopened during the job.

Slow routes to GitHub may close a long download before the end. The worker then
requests the remaining bytes with an HTTP Range request and keeps hashing in file
order. A server that ignores the range restarts the file from the first byte. The
complete archive must still match the size and SHA-256 from the signed manifest.
If an attempt and the eight retries after it bring no new bytes, the update stops
with `release_unavailable`. The private host settings `download_retries` and
`download_retry_delay` change these limits. The dialog shows how many times the
download was resumed.

Free space is checked before downloading, loading new image layers and backing
up data. Existing base layers are reused. Insufficient space stops the update
before panel replacement and appears in the dialog. The default reserved
remainder is the larger of 2 GiB and 10% of the filesystem. Private host settings
minimum_free_bytes and minimum_free_percent define that reserve. Temporary
layer extraction and the SQLite snapshot must fit in addition to it. The reserve
is checked again after image loading and backup.

Scheduled controller work also shares the update barrier. Native counter reads
that reset remote counters wait until cutover verification finishes. One-off
startup jobs resume after verification. This keeps a failed candidate from
consuming counters that would be lost when its database is rolled back.
A durable cutover marker keeps the barrier active after a worker crash releases
its OS lock. Recovery clears it only after success or completed rollback.

Readiness requires the expected version, console, a token-authenticated API
response, a working private hub API, current Alembic heads and a heartbeat from
the actual scheduler. A
static HTML response is insufficient. The private readiness token is never
returned by the API. The heartbeat itself has no writes or counter reads.

Replacement preserves operator environment overrides. Inherited base-image
defaults, including PATH and Python settings, follow the new image. Compose
ownership labels are removed from worker-created replacements. Reconcile the
deployment file explicitly before running Compose again.

The panel briefly restarts during replacement. Subscription downloads require
the panel to answer. Existing running node cores continue under their own service
management. Cold node startup, offline quota reconciliation and independent
subscription hosting follow the boundaries in [OPERATIONS.md](OPERATIONS.md).

## Backups and recovery

Private update state defaults to `/var/lib/rime-updater` on the host. The worker
keeps the two newest completed rollback sets and removes older owned update
containers and unused owned image tags after verifying their identity and state.
This retention applies
only to update backups. Maintain independent server backups as well.

If Docker becomes temporarily unavailable during rollback, the service retries
the recovery before accepting another update. Inspect the host journal and
private update state when the dialog reports that recovery needs attention.

```sh
sudo systemctl status rime-update.path rime-update.service
sudo journalctl -u rime-update.service --since today
```

## Explicit rollback after success

The host CLI can install the image preceding a selected successful job. It keeps
the **current** database and data files, including users created after that job,
and creates a fresh checkpoint for failure recovery. The migration revision
must match the target checkpoint. Otherwise it refuses before replacing the
panel; it neither downgrades a schema blindly nor discards later user changes.

Run from the installed worker directory:

```sh
sudo python3 -m update_runtime.worker --config /opt/rime-updater/config.json \
  --rollback <successful-32-hex-job-id> --confirm rollback
```

Targets older than 0.9.0 are refused, with
`downgrade_requires_preparation`. This guard covers the supported worker path.
The guard also avoids restoring the older unauthenticated hub API. Root can
bypass it with raw Docker commands, which do not constitute safe rollback.

## Planned handover to a reset-based collector

An older collector against unchanged cumulative core counters can charge accepted
traffic again. Restoring an old panel alone does not reset remote counters.
Before any planned handover, qualify a target controller compatible with the
node's certificate-authenticated API. Unmodified rc6 lacks this support; prepare
a compatible controller or a separately qualified node-runtime transition.
The worker does not offer a blind rc6 rollback.

While 0.9.0 is running, a sudo administrator can call
`POST /api/system/updates/downgrade/prepare` with
`{"version":"0.2.0-rc6","confirmation":"restart-qualified-cores"}`.
It acquires maintenance, collects the final cumulative usage, restarts available
qualified cores and verifies changed epochs. An unavailable qualified node or
unverified restart fails preparation. Partial failure keeps maintenance active.

Success records verified epochs in the persistent database and private queue,
leaving mutations and scheduled collectors paused. Save a fresh database/key
checkpoint. Stop the current panel before starting the compatible older collector
with the **current** database, signing key and vault key. It can consume only
traffic since the fresh epochs. Restarts interrupt sessions briefly; bytes
produced between the final sample and restart cannot be reconstructed. User
keys are preserved.

To abandon preparation, sudo can call
`POST /api/system/updates/downgrade/cancel`. It invalidates preparation and resumes
0.9.0 against the new epochs. Never remove maintenance files by hand or run two
collectors at once.

## Publishing compatible assets

A Rime GitHub Release contains `rime-release.json`, `rime-release.sig`,
`rime-linux-amd64.tar.gz` and `SHA256SUMS`. The archive is a Docker image export.
The manifest uses schema 1 and binds version, Git revision, archive digest and
portable image-config digest. Docker's local image/index identifier may differ
from that portable digest.

The workflow verifies backend/frontend checks, consecutive updates and actual
automatic/manual rollback before publication. Actions use immutable commit pins.
Assets and detached signature are uploaded to a draft, the manifest is uploaded
last, then the draft is published. Already public releases are not overwritten.
Unsigned inherited upstream tags are omitted from the catalog.

Before publication, provision RIME_RELEASE_SIGNING_KEY in the protected
release-signing environment and require independent approval for that environment.
Keep its private key out of Git and ordinary build jobs. The exporter refuses a
key that differs from the pinned public root. Export with
`scripts/export_release.py --signing-key <private-ed25519-pem>` only in the reviewed
signing environment. Rotation requires a separately reviewed public-key update
in both panel and worker; never download trust keys from the release itself.
