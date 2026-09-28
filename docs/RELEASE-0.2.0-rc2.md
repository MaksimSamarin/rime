# Rime 0.2.0-rc2

RC2 unifies the administrative UI and adds user tags, per-node access, fleet
resource monitoring, incident actions and per-node traffic quotas. Existing
subscription identities remain stable. Node quota blocking deliberately leaves
subscription generation unchanged.

## Build and evidence

Build from the repository Dockerfile. Both base images are pinned by digest;
Python dependencies use the qualified `requirements.lock` constraints and the
dashboard uses `package-lock.json`. A release source archive must include a
SHA-256 manifest of tracked and intentionally included untracked source files.
Record its digest, final OCI image ID, dependency freeze and test results. A
working-tree source archive is not a substitute for an approved Git commit/tag.

Run Python unit tests, JavaScript checks and the isolated real-core E2E harness
with `CONSOLE_ACL=1 NODE_QUOTAS=1`. Before production, rehearse this exact image on
a fresh private database snapshot, compare all previously issued subscription
URLs and formats, test legacy bridges, then roll back to the old image using
the upgraded database. Public source archives/images must contain no runtime
credentials, customer databases, site-specific subscription endpoints or demos.

## Panel-first rollout

Preserve the panel address, ports, database, signing material, UUIDs, user creation
dates and private legacy subscription additions. Merge only those additions into
the new subscription implementation; do not overwrite the new implementation
with a complete older file. Keep private overlays out of the public repository
and mount them at runtime. Test the exact overlay/startup command before use.

During the rollback-capable panel-only pilot, keep node-specific access and node
quotas disabled, retain current user allowances, and keep `safe_period_reset`
false. Legacy Hy2 bridges do not implement the new node policy/accounting, and
the old panel cannot enforce new Rime-only policies after rollback. Upgrade
Hy2 agents individually afterwards; enable advanced restrictions and safe user
resets only after that phase is qualified.

Use image/Compose rollback while preserving the latest database. Restoring an
older database against newer node journals requires explicit reconciliation.
Public-network TLS/UDP reachability, real client applications and sustained
observation remain production pilot checks; offline rehearsal cannot prove them.
