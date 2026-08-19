# Repository guidance

This repository is intended to be safe for public sharing.

- Never commit Databricks profiles, workspace URLs/IDs, account IDs, metastore IDs, warehouse IDs, principal IDs, tokens, client secrets, private keys, tenant data, or live command output.
- Keep environment-specific desired state outside Git. Commit only redacted examples.
- All authorization paths must fail closed. A table without a validated workspace scope is admin-only by default.
- Use account groups, not workspace-local groups, in production policy configuration.
- Run `make check` and `git diff --check` before declaring a change complete.
- Record architecture decisions and verification evidence in `miniwiki/accelerator.md`; do not add a second task tracker.
