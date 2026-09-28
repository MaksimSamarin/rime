# Contributing to Rime

Open issues and pull requests in [this fork](https://github.com/MaksimSamarin/rime).
Use a feature branch from `master`. Describe the concrete problem, resulting
behavior, relevant tests and any migration or rollback limits.

## Project layout

| Path | Purpose |
|---|---|
| `app/` | FastAPI backend, models, migrations and compatibility routes |
| `hy2bridge/` | Fleet accounting, node agents, monitoring and management |
| `hy2bridge/web/` | The single Rime console: HTML, CSS and JavaScript |
| `cli/`, `rime-cli.py` | Administrative CLI; old entry point remains an alias |
| `xray_api/`, `core-patches/` | Xray client and qualified Hy2 changes |
| `tests/` | Unit and isolated transport/console regression tests |
| `docs/` | Operations, capabilities, limits and synthetic UI screenshots |

## Development and testing

The console is served directly by FastAPI. It needs no React, Vite or npm build.
Node.js is used for syntax checks and the JavaScript test runner only.
Changes to static files are available on refresh; `DEBUG=true` enables backend
reload for isolated development. Never enable a development server against a
production database.

Follow [TESTING.md](docs/TESTING.md). Keep changes focused, preserve existing
subscriptions and credentials, and verify changes to accounting or node control
with the isolated real-core harness. Run one controller per SQLite database.
Database and node journal backups must be consistent before migration.

## Reports and screenshots

Include the Rime/core versions, a reproducible scenario and sanitized diagnostics.
Do not attach environment files, private keys, subscription URLs, database copies
or full server inventories. Use [synthetic fixtures](docs/SCREENSHOTS.md) for public
screenshots. State when a result is simulated rather than a live network probe.

## CLI and compatibility

Run `python rime-cli.py --help` from the repository root. CLI commands live in
`cli/` and use Typer. The old script name and environment variables remain aliases.
Keep the original license and notices; see [NOTICE.md](NOTICE.md).
