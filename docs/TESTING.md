# Testing

The unified console adds `tests/test_access.py` for per-node policy/config/host
filtering, identity reuse, tag reports and incident recovery comments. Run the
existing isolated `tests/e2e.py` harness with `CONSOLE_ACL=1` to additionally verify
selected-node TCP access, rejection on other Hy2/local Xray nodes, restart
persistence and restoration through an existing subscription URL. These tests
require the same isolated binaries and fixtures as the base E2E harness.

Fast checks from the repository root:

```sh
python -m pip install -r requirements-panel.txt
python -m unittest discover -s tests -p 'test_*.py' -v
cd app/dashboard
npm ci
VITE_BASE_API=/api/ npm run build -- --outDir build --assetsDir statics
```

The transport test uses Linux socket/TLS behavior and is skipped on Windows.
`Rime checks` runs both Python and TypeScript builds on Linux. CI does not deploy,
connect to SSH targets or publish images. Image builds are local until release.

The image job also runs `tests/console_creation.py` in its newly built image with
no external network, a temporary database and synthetic accounts. It verifies
VLESS inbound defaults, external Hy2 links, real VLESS payload, selected-node
filtering, disabled creation, editing and previously issued URLs after restart.
This regression harness does not require separate Hy2 binaries or lab certificates.

Node-quota regression tests are in `tests/test_node_quotas.py`. The isolated E2E
harness additionally supports `NODE_QUOTAS=1`: Hy2/VLESS node-wide enforcement,
other-node availability, old subscription continuity, persistence across panel
restart, manual reset and an accelerated scheduled boundary in the private fixture.

The isolated E2E suite also starts a dedicated Hysteria client as the monitoring
tunnel. It verifies an echoed payload, stops that client to produce
`traffic_failed`, starts it again, and confirms that a successful recheck resolves
the incident. Browser QA covers direct hash routes, asset cache headers, user
typeahead, node edit persistence, manual checks from node and incident screens,
and desktop/mobile overflow.

`tests/e2e.py`, `core_crash.py`, `provision_traffic.py`, and `restore.py` are inherited
lab harnesses, not generic production tools. They require a prepared isolated
Linux lab, pinned Xray/patched Hysteria binaries and synthetic data. They must
never be run against a production database or Docker namespace. The legacy-link
fixture uses reserved `.invalid` domains. No deployment credentials are included.

To reproduce core tests, check out Hysteria `app/v2.12.3` into a separate directory,
apply `python core-patches/apply.py <source>`, copy `durable_test.go` into
`extras/trafficlogger/fleet_durable_test.go`, and run Go tests in that module.
Retain the upstream LICENSE when packaging. The node binary must be named
`hysteria-fleet`; an upstream unpatched binary does not provide durable accounting.
