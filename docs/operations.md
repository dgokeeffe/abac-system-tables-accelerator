# Operations guide

## Rollout sequence

1. Create dedicated account groups for each BU, trusted facade admins, and a materialized-view run-as service principal. Assign only the groups needed in the deployment workspace.
2. Inventory existing direct grants on `system`; remove consumer bypasses through the organization's normal change process.
3. Resolve active workspaces to canonical IDs. Reject absent, deleted, or ambiguous display-name matches.
4. Place desired state outside Git, validate it locally, and run `plan` with an explicitly selected administrator profile.
5. Review all dispositions. `admin_only` and `unavailable` are safe defaults, not errors to bypass. Approve each `account_shared` rationale separately.
6. Confirm the facade catalog/schema and governed tag names do not overlap another governance domain. The schema must be dedicated to this accelerator; unrelated objects block planning.
7. Apply the exact reviewed `planDigest` in an isolated environment. It binds desired config, source discovery, existing facade objects/grants, and exact steps. Keep row-data-free evidence outside Git.
8. Wait for bounded tag propagation, then inspect table/column tags, `SHOW EFFECTIVE POLICIES`, ABAC information schema, and facade grants.
9. Verify every BU through a representative service principal using the SQL Statement Execution API. Include positive, cross-BU, unassigned-workspace, account-shared, admin-only, and direct-source-denied cases.
10. Revoke OBO tokens immediately. Promote only after independent governance/security review.

## Failure and rollback

Stop on the first failed apply step. Do not blindly rerun until object and grant state is inspected. Every apply revokes all discovered non-trusted direct catalog/schema/table privileges—including already-correct consumer grants—before replacement, so plan a read interruption. It restores only declared navigation plus object-level consumer `SELECT` after effective-policy gates pass; a failure therefore leaves consumers denied. Schema-wide `SELECT` is reserved for configured trusted principals, so materialization support tables and unexpected future objects are not inherited by consumers. It drops only stale materialized views carrying the accelerator's known governed disposition tag and refuses unexpected objects. `CREATE OR REPLACE` makes functions, materialized views, and the policy convergent, while governed tags require an exact allowed-value-set match. Grants and revokes are idempotent.

Rollback is an administrator-owned change. Revoke consumer facade grants first to fail closed, then remove the policy/materialized views/functions if required. Do not delete governed tags while policies still reference them; Databricks fails queries closed when a referenced governed tag disappears.

## Drift

Re-run `plan` after system schemas are enabled, source schemas change, group/workspace assignments change, or Databricks introduces new system tables. Every discovered table is classified. A source with invisible columns is `unavailable`, and a non-STRING `workspace_id` cannot be forced to `workspace_scoped`.

## Evidence

Retain only:

- config and plan digests;
- disposition counts and standard system-table names;
- statement status plus hashed statement references;
- scenario/check pass-fail plus aggregate observed-scope counts and zero-violation assertions;
- policy/tag/grant assertions with tenant identifiers redacted.

Do not retain query rows, tokens, principal IDs, hosts, workspace IDs, or warehouse IDs in Git.
