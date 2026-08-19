# Contributing

1. Keep environment-specific desired state and all credentials outside Git.
2. Read `AGENTS.md`, `SECURITY.md`, and `miniwiki/accelerator.md` before changing policy logic.
3. Preserve fail-closed defaults. A widening change needs explicit security review.
4. Add deterministic tests for config, SQL, planning, execution failure, and verification behavior.
5. Run:

```bash
make check
git diff --check
```

Do not use live tenant identifiers or command output in tests, fixtures, docs, commits, issues, or pull requests. Use account groups rather than workspace-local groups in production examples.

A pull request should describe the acceptance contract, affected authorization paths, validation commands/results, connected testing status, and residual risks. Deployment, grants, and merge remain explicit human decisions.
