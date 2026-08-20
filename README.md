# Databricks system tables ABAC accelerator

Give each business unit direct access to Databricks system tables while Unity Catalog automatically hides rows for workspaces it does not manage.

System tables contain metastore-wide metadata. A plain `SELECT` grant can expose every workspace. This accelerator applies governed tags and one ABAC row-filter policy **directly to the original `system` tables**, then grants every configured BU account group access to every workspace-scoped and explicitly approved account-shared table.

> **Status: alpha reference accelerator.** Test in a non-production metastore and review the effect on existing system-table readers before rollout.

## One concrete example

Assume the Platform Operations account group manages workspaces `101` and `102`:

```json
{
  "consumer_groups": [
    {
      "name": "platform_operations_system_table_readers",
      "workspace_ids": ["101", "102"]
    }
  ]
}
```

A group member queries the original table normally:

```sql
SELECT * FROM system.billing.usage;
```

Unity Catalog evaluates the ABAC row filter for every row:

| Row `workspace_id` | Result |
|---|---|
| `101` | returned |
| `102` | returned |
| `999` | hidden |
| `NULL` | hidden |

No copied data, materialized view, refresh job, or caller-supplied `WHERE` clause is involved.

## How it works

```text
Administrator configures: account group -> workspace IDs
        |
        v
Accelerator tags original system tables and workspace_id columns
        |
        v
One ABAC policy on CATALOG system finds those governed tags
        |
        v
Policy UDF checks caller's account groups + each row's workspace_id
        |
        v
BU queries system.<schema>.<table> and sees assigned workspaces only
```

The small tenant-owned **governance schema** stores only:

- the SQL row-filter function;
- immutable deployment metadata; and
- a manifest of `SELECT` grants created by the accelerator.

It never stores system-table rows.

## Important default-deny behaviour

The catalog policy applies to **`account users` except configured trusted principals**. Once a table carries the configured `workspace_scoped` governed tag:

- a configured BU group sees its assigned workspace rows;
- a principal in no configured BU group sees zero rows; and
- a trusted principal is exempt and sees the unfiltered table, subject to normal grants.

This also restricts pre-existing readers of a tagged system table unless they are configured or trusted. Review that impact before applying.

## Terms

| Term | Meaning |
|---|---|
| **Consumer group** | Databricks account group receiving direct system-table access |
| **Workspace assignment** | Workspace IDs that the group manages |
| **Governed tag** | Controlled table/column label used to select the ABAC policy |
| **ABAC policy** | Catalog-scoped Unity Catalog policy that attaches the row filter |
| **Governance schema** | Tenant-owned control-plane schema containing the UDF and deployment state only |
| **Representative service principal** | Test identity placed in one consumer group; it authenticates as itself and does not impersonate a user |

## How every system table is handled

Every discovered table receives one explicit mode:

1. **Workspace-scoped** — has a `workspace_id STRING` column; tagged and protected by the row filter.
2. **Account-shared** — has no `workspace_id` column and is explicitly approved, with a written rationale, for all configured consumer groups. The approval also applies automatically to consumer groups added in future configurations, so treat it as a durable global-sharing decision.
3. **Admin-only** — cannot be safely split by workspace and is not granted to consumers.
4. **Unavailable** — source metadata cannot be inspected safely, so no grant or tag is added.

A table with any discovered `workspace_id` column can never be marked account-shared. Nothing is silently shared.

## What apply changes

The accelerator:

1. creates the tenant-owned governance catalog and schema;
2. creates `managed_grants` and `deployment_state` control tables;
3. acquires a renewable deployment lease before any grant, tag, UDF, or policy mutation;
4. revokes only `SELECT` grants recorded in its previous manifest;
5. creates or validates the governed tags;
6. creates the group-aware, fail-closed SQL UDF;
7. creates the ABAC row-filter policy on `CATALOG system` before any policy-selecting tag is assigned;
8. for each workspace-scoped source, tags `workspace_id` first and then tags the table, avoiding a tagged-but-unfiltered interval;
9. proves that policy is effective on every workspace-scoped table;
10. records the pending configuration digest, then records all desired direct grants as `PENDING`;
11. grants `USE CATALOG`, required `USE SCHEMA`, and object-level `SELECT` to consumer groups;
12. marks the manifest rows `ACTIVE`;
13. records the successful configuration digest and clears the pending digest; and
14. releases its lease. A process that dies stops renewing, allowing bounded stale-lease recovery after 30 minutes.

External grants not recorded in `managed_grants` are never revoked. If apply fails after writing `PENDING`, the next plan loads and revokes those tuples before retrying.

The accelerator never automatically removes a direct governed tag. A stale `workspace_scoped` tag keeps the row filter and remains fail-closed. A stale `account_shared` tag has no row filter: managed `SELECT` grants are closed, but unrelated external grants must be audited before manual cleanup. The workspace-column tag is accepted only on a column named `workspace_id`.

## Configuration v2

Start with [`examples/config.example.json`](examples/config.example.json), but keep real workspace IDs and principal names outside this public repository.

```json
{
  "version": 2,
  "governance": {
    "catalog": "system_tables_governance",
    "schema": "abac"
  },
  "tags": {
    "table_key": "system_table_scope",
    "workspace_column_key": "workspace_scope_column"
  },
  "consumer_groups": [
    {
      "name": "bu_alpha_system_table_readers",
      "workspace_ids": ["1111111111111111"]
    }
  ],
  "trusted_principals": ["system_table_governance_admins"],
  "overrides": []
}
```

Use canonical decimal workspace IDs, not display names. Display names can be reused after deletion or recreation.

Version 1 copied system data into materialized views and is deliberately rejected. See [v1 to v2 migration](docs/migration-v1-to-v2.md). Old copied objects are not dropped automatically.

## Operator workflow

### 1. Install

Requirements:

- Python 3.11+
- Databricks CLI 0.292+
- a serverless SQL warehouse
- an explicit administrator profile
- privileges to create governed tags, tag system tables/columns, create the catalog policy, manage the governance schema, and grant system-table access
- production **account groups**, not workspace-local groups

```bash
uv sync --frozen
. .venv/bin/activate
```

### 2. Plan — read only

```bash
export DATABRICKS_WAREHOUSE_ID='<kept-outside-git>'

abac-system-tables plan \
  --config /secure/path/config.json \
  --profile '<administrator-profile>' \
  --output /secure/path/plan.json
```

The redacted plan shows each table's mode, prior managed-grant count, stale protected tags, ordered operation kinds, and hashed targets. It does not print principal names, workspace IDs, SQL text, or tenant-specific grant targets.

`planDigest` binds the configuration, discovered tables, persisted deployment state, prior managed grants, current managed tags, and exact generated SQL.

### 3. Apply the reviewed plan

```bash
abac-system-tables apply \
  --config /secure/path/config.json \
  --profile '<administrator-profile>' \
  --confirm '<planDigest-from-plan>' \
  --output /secure/path/apply-evidence.json
```

Apply re-runs discovery. Any drift changes the digest and blocks mutation. Prior accelerator-managed `SELECT` grants are revoked before policy/tag changes and restored only after all policy gates pass, so plan a temporary interruption for managed readers.

`deployment_state` fixes the state version, tag keys, catalog policy scope, and policy name. Changing those immutable identifiers requires an explicit migration; apply blocks rather than losing track of prior grants. A pre-existing `workspace_scope` policy without compatible deployment state is treated as foreign and is never silently replaced. Other catalog row-filter policies are counted in the plan, and any policy that also resolves on a managed table causes the effective-policy gate to stop before grants.

### 4. Verify as representative service principals

Each profile must authenticate as the SP itself. The SP must belong to exactly the consumer group named by its scenario and must not be trusted.

```bash
abac-system-tables verify \
  --config /secure/path/config.json \
  --scenarios /secure/path/verify.json \
  --warehouse-id "$DATABRICKS_WAREHOUSE_ID" \
  --output /secure/path/verify-evidence.json
```

Verification accepts only direct `system.<schema>.<table>` relations:

- `scoped` requires non-empty permitted scope and zero null, unassigned, or cross-BU rows;
- `shared` must be readable; and
- `denied` must fail with an authorization-specific error, not a timeout or missing object.

Verification also proves the authenticated SP identity, intended consumer-group membership, absence from trusted exemptions, and the resulting row scope. In the authorised sandbox, all three representative SPs returned `is_account_group_member('account users') = true`; the direct catalog policy governed them and each direct system-table check returned one permitted workspace with zero cross-workspace violations.

See [`examples/verify.example.json`](examples/verify.example.json) and [service-principal testing](docs/obo-testing.md).

## Safety boundaries

- Tags are applied to original system tables only after classification.
- The row-filter UDF returns false for null, unknown, and unmapped workspace IDs.
- Policy scope is fixed to `CATALOG system` and applies to account users except explicit trusted principals.
- Consumer access is direct object-level `SELECT`; admin-only and unavailable tables receive no managed grant.
- Only grants recorded in the manifest are revoked; unrelated external grants are untouched.
- Stale direct tags are not automatically removed; workspace-scoped tags remain filtered, while account-shared tags require external-grant audit.
- Partial or paginated verification evidence is rejected.
- Normal output contains no credentials, tenant IDs, rows, principal names, or raw statement IDs.

See [`SECURITY.md`](SECURITY.md) and [`docs/operations.md`](docs/operations.md).

## Databricks bundle

[`databricks.yml`](databricks.yml) packages the wheel and contains generic governance variables only.

```bash
databricks bundle validate --strict \
  -t validation \
  --profile '<administrator-profile>'
```

Bundle validation does not deploy governance. `apply --confirm <planDigest>` is the mutation boundary.

## Public-repository safety

Never commit profiles, workspace URLs, tenant IDs, tokens, client secrets, private keys, production configuration, raw query output, or connected evidence.

## Limitations

- Direct tagging and catalog ABAC require supported Databricks capabilities and sufficient administrator privileges.
- Existing readers of a newly tagged workspace-scoped table are default-denied unless configured or trusted.
- Navigation grants may remain after a group is retired; exact object-level `SELECT` is the managed security boundary.
- The accelerator does not remove unrelated external grants.
- Governed-tag propagation can take several minutes.
- Apply is serialized with a renewable governance-state lease. A process that dies can be recovered after the 30-minute stale timeout; operators should not run a single blocking SQL operation longer than that timeout.
- The governance schema and its state tables are a privileged security boundary. Only the deployment identity and trusted governance administrators may write them; manifest rows are validated against phase digests and tagged discovered targets before any revoke is generated.
- Stale governed tags require a separately reviewed manual cleanup.
- Old v1 copied catalogs and materialized views require separate, explicitly approved cleanup.

## Development

```bash
PYTHONPATH=src uv run --no-sync make check
git diff --check
```

Checks include formatting, lint, strict typing, tests with coverage, package build, example parsing, and secret scanning.
