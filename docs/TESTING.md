# Testing

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
