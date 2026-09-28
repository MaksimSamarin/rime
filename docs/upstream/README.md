# Upstream provenance

Rime started from Marzban **0.8.4**, commit `7f396db`.
The original license, copyright notices and Git history are retained.
See [NOTICE](../../NOTICE.md) and [LICENSE](../../LICENSE).

The former translated guides, promotional badges and dashboard screenshots
described a different product. They are no longer distributed as Rime setup
instructions. Historical material remains available in the upstream repository:

- [Original source and guides at the fork base](https://github.com/Gozargah/Marzban/tree/7f396db)
- [Upstream node component](https://github.com/Gozargah/Marzban-node)

For the current product, use the [Rime README](../../README.md),
[Russian guide](../../README-ru.md) and [operations guide](../OPERATIONS.md).

## Intentional compatibility names

The `/var/lib/marzban` data path, database schema, existing environment variables,
subscription routes and `marzban-cli.py` alias preserve existing installations.
The pinned runtime base and native-node component retain their upstream names.
The active interface is `hy2bridge/web`; `/dashboard/` is a compatibility redirect.
Renaming credentials, tables or service protocols is not a branding operation.
