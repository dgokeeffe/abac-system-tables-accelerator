# Security policy

## Reporting

Report suspected vulnerabilities privately. Do not include credentials, tenant data, workspace URLs, identifiers, or live query output in public issues.

## Threat model

The deployer is a trusted Unity Catalog governance administrator. Consumer identities are Databricks account groups managed by the organization's identity lifecycle.

Primary threats:

- a workspace-scoped system table being granted without the direct ABAC policy;
- a missing, null, mistyped, or reused workspace ID widening row access;
- a table with `workspace_id` being misclassified as account-shared;
- removal or reassignment of governed tags disabling protection;
- an over-broad trusted exemption;
- a removed group retaining an accelerator-created direct grant;
- failed apply leaving an untracked grant;
- incompatible state/tag/policy identifiers losing track of prior grants;
- SQL injection through configuration or discovered metadata;
- credentials or tenant metadata entering Git or normal logs; and
- unrelated pre-existing grants providing an access path the accelerator does not own.

## Controls

- Strict v2 JSON parsing rejects unknown fields, duplicate keys, unsafe values, and secret patterns.
- Workspace display names are rejected; only decimal IDs are accepted.
- `workspace_id STRING` is required for automatic workspace scoping.
- Any discovered `workspace_id` prohibits account-shared classification.
- Account-shared access requires an explicit override and rationale.
- The UDF denies null, unknown, and unassigned workspace IDs.
- One policy is fixed to `CATALOG system`, targets `account users`, and exempts only configured trusted principals.
- The catalog policy is installed before policy-selecting tags; for workspace-scoped sources, the `workspace_id` column tag is assigned before the table tag activates the policy.
- Governed tags are applied directly to original system tables and columns.
- Consumer groups receive object-level `SELECT`, never an accelerator-created schema-wide `SELECT`.
- A unique renewable deployment lease is conditionally acquired and proven before governance mutation. Apply heartbeats before each later step, releases only its own token, and permits crashed-writer recovery after a bounded timeout.
- `deployment_state.pending_config_digest` is persisted before `PENDING` grant rows; success moves that digest to `last_successful_config_digest` and clears pending state.
- Before any revoke is generated, each manifest row must match its pending/active deployment digest and target a discovered system table carrying this accelerator's table tag.
- Every validated prior `PENDING` or `ACTIVE` manifest tuple is revoked before state is cleared and rebuilt.
- A missing or malformed deployment singleton blocks planning; `deployment_state` also makes tag keys, policy scope/name, and state version immutable without migration.
- A fixed `workspace_scope` catalog policy without compatible deployment state is treated as foreign and is never silently replaced. Effective-policy gates require it to be the only row filter on each managed target before grants.
- Unrelated external grants are not revoked or claimed as accelerator-managed.
- Stale workspace-scoped tags remain filtered and fail closed. Stale account-shared tags have no row filter, so managed grants close but unrelated external grants require audit. A workspace-column tag on any non-`workspace_id` column blocks planning.
- Plan confirmation binds configuration, source discovery, persisted state, managed tags, grants, and exact SQL.
- Verification authenticates as representative SPs, proves group/trusted status, and accepts only direct `system.*` relations.
- Normal output omits credentials, row data, tenant IDs, principal names, and raw statement IDs.

## Operational requirements

- Use account groups, not workspace-local groups.
- Restrict governed-tag assignment, policy management, governance-schema ownership, control-table writes, and trusted exemptions. Governance state is a privileged security boundary; compromise of its owner is outside the manifest's integrity guarantees.
- Audit pre-existing direct grants before tagging because the policy default-denies unconfigured readers.
- Run representative-SP positive, cross-workspace, shared, and authorization-denial checks.
- Revoke temporary OAuth/OBO credentials immediately.
- Keep real configuration and connected evidence outside this repository.
- Treat direct tag removal and v1 copied-object cleanup as separate reviewed changes.

## Unsupported claims

A Databricks profile authenticates one identity. The verifier does not impersonate arbitrary users. A service principal is representative only for account groups it actually belongs to.

The accelerator manages only grants recorded in its manifest. It does not prove that unrelated account roles, external grants, or ownership paths are absent; production acceptance must audit those separately.
