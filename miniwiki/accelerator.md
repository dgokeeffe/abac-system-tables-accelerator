# ABAC system tables accelerator

Databricks system tables contain metastore-wide metadata. Business units that manage only a subset of workspaces should query the original system tables but see only rows for their assigned workspace IDs.

## Correct architecture

The accelerator applies ABAC directly to `system` tables. There is no copied system data, materialized-view facade, refresh schedule, or published data catalog.

```text
Account groups + assigned workspace IDs
              |
              v
Tenant-owned governance UDF
              |
              v
One ABAC policy on CATALOG system
              |
       governed table/column tags
              |
              v
Original system tables + direct object SELECT grants
```

A small tenant-owned governance schema stores only:

- the group-aware `workspace_allowed(workspace_id)` SQL UDF;
- immutable deployment metadata; and
- the exact direct `SELECT` grants managed by the accelerator.

It never stores system-table rows.

## Architecture correction and evidence

The initial v1 implementation incorrectly assumed that Databricks-owned system tables could not receive tenant-managed governed tags or ABAC policies and therefore created materialized copies. Live testing disproved that assumption:

- a governed tag was applied directly to `system.access.workspaces_latest`;
- the governed workspace-column tag was applied directly to `workspace_id`;
- a table-scoped direct row-filter policy succeeded;
- a catalog-scoped row-filter policy on `CATALOG system` succeeded; and
- three representative service principals querying the original system table each saw exactly one assigned workspace.

The v1 copy architecture is superseded. Configuration version 1 is rejected. Cleanup of the old copied facade is separate and destructive; it is not part of v2 apply.

## Direct-v2 behavior

Every discovered system table receives one explicit handling mode:

1. `workspace_scoped`: a `STRING workspace_id` column exists; the original table and column are tagged, the catalog policy applies, and configured groups receive direct table `SELECT`.
2. `account_shared`: no `workspace_id` exists and an administrator has explicitly approved the table, with rationale, for every configured group and future groups.
3. `admin_only`: the table cannot be safely divided by workspace and receives no managed consumer grant.
4. `unavailable`: source metadata cannot be inspected safely and no tag or grant is added.

A source with any discovered `workspace_id` column cannot be marked account-shared.

## Policy semantics

The single policy is attached to `CATALOG system` and selected by governed table and column tags. It applies to `account users` except configured trusted principals.

The UDF returns true only when:

- `workspace_id` is non-null;
- the session principal belongs to a configured consumer account group; and
- the row's `workspace_id` is assigned to that group.

A configured identity receives the union of its configured group assignments. An unconfigured, non-trusted reader of a tagged workspace-scoped table sees zero rows even if another system-table grant exists. Trusted principals remain unfiltered and must be narrowly controlled.

In the authorised sandbox, representative service principals returned `is_account_group_member('account users') = true` and were governed by the direct catalog policy. Verification still checks this behavior from effective query results rather than assuming it for another tenant.

## Managed grant state

Direct system tables live in a shared catalog, so the accelerator must not revoke unrelated grants. The governance schema contains:

- `managed_grants`: only direct `SELECT` tuples created by this accelerator, with `PENDING` or `ACTIVE` status and a config digest;
- `deployment_state`: fixed state version, tag keys, policy scope/name, last successful digest, and any pending digest.

Apply performs:

1. exact plan-digest confirmation and identity validation;
2. control-table creation/validation;
3. revocation of prior manifest grants only;
4. governed-tag and UDF setup;
5. catalog-policy creation/replacement before assigning policy-selecting tags;
6. direct system-table and `workspace_id` tagging;
7. an effective-policy gate for every workspace-scoped table;
8. pending deployment/manifest state;
9. direct navigation and table `SELECT` grants;
10. manifest activation and successful deployment-state update.

A later plan rejects partial control tables, a missing singleton, incompatible immutable state, manifest phase/digest mismatch, undiscovered or untagged manifest targets, a foreign fixed-name policy, and the workspace-column tag on any non-`workspace_id` column.

The governance schema is a privileged security boundary. Only the deployment identity and trusted governance administrators may write its state.

## Stale tags

Direct tags are never removed automatically.

- A stale `workspace_scoped` tag remains protected by the row policy and is fail-closed.
- A stale `account_shared` tag has no row filter. Accelerator-managed grants are closed, but unrelated external grants require explicit audit before manual tag cleanup.

## Connected verification (redacted)

The temporary validation policy `direct_catalog_workspace_scope_test` was explicitly dropped before the v2 apply, avoiding silent replacement or multiple-row-filter conflict. A direct v2 deployment then completed successfully through the SQL Statement Execution API:

- all 40 enabled system tables were classified;
- 35 were workspace-scoped;
- one account-global reference table was explicitly account-shared;
- four account-global tables remained admin-only;
- 35 direct effective-policy gates passed;
- 108 direct object `SELECT` grants were recorded and activated; and
- the initial direct apply completed 264 steps, and the final serialized repeat apply completed 373 planned steps with a deployment lease, policy installation before policy-selecting tags, and workspace-column tags before workspace-scoped table tags.

Three account-group-backed representative service principals authenticated as themselves with short-lived OAuth M2M credentials. Each queried the original `system.access.workspaces_latest` table and observed exactly one assigned workspace with zero cross-workspace violations. Each could read the reviewed direct account-shared reference. Temporary OAuth secrets were revoked immediately after verification.

A follow-up read-only plan loaded the deployment singleton and all 108 active managed grants, proving persisted-state discovery and repeat-apply reconciliation. The final apply acquired and released its token-owned deployment lease; post-apply state showed no lease or pending digest. Three representative SP scenarios were rerun after that apply and again returned one assigned workspace each.

## Environment limitation

The sandbox's broad `account users` group carries an account-admin role. Consequently, an admin-only direct-source denial cannot be accepted there because every representative SP inherits access independently of accelerator-managed grants. This is disclosed rather than reported as a pass. Production acceptance must run the authorization-specific admin-only denial check in a least-privilege tenant.

## v1 coexistence and cleanup

The old copied facade remains as a rollback path for now. Its refresh/run-as identity must remain temporarily trusted while the direct policy is active; otherwise a v1 refresh can permanently copy filtered or empty data. Verify a successful v1 refresh during coexistence.

After an observation period, cleanup requires a separate approved change to revoke v1 access, remove v1 policies/UDFs/materialized views and pipelines, and drop the old facade only after confirming it contains no unrelated objects.

## Verification evidence

Offline checks pass:

- Ruff formatting and lint;
- strict mypy;
- 80 unit tests with at least 85% coverage;
- package build and example parsing;
- repository secret scan;
- strict Databricks bundle validation; and
- `git diff --check`.

The public repository is https://github.com/dgokeeffe/abac-system-tables-accelerator. Tenant identifiers, configuration, raw plans and connected evidence remain outside Git.

## Remaining operational decisions

- Run admin-only denial tests in a production-like least-privilege tenant.
- Keep direct policy exemptions and tag-assignment permissions minimal.
- Enforce a single-writer deployment lane for each governance schema.
- Audit unrelated external system-table grants, especially on account-shared or stale-tagged tables.
- Decide when the v1 rollback facade and retained regression identities should be removed.
