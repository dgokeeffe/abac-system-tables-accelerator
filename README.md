# Databricks system tables access accelerator

Give each business unit access to **only the system-table rows for the workspaces it manages**.

Databricks system tables contain data for an entire metastore. Granting a BU direct access can therefore reveal metadata from every workspace. This accelerator creates a separate, governed catalog where each BU can query familiar system-table data but only see its assigned workspace IDs.

> **Status: alpha reference accelerator.** Test it in a non-production environment. The redacted CLI plan is a safety summary, not a substitute for your organization's review of tenant-specific grants and changes.

## The idea in one example

Assume the Platform Operations account group is responsible for workspaces `101` and `102`. The administrator records that assignment:

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

The accelerator keeps the Databricks-owned `system` table private. It publishes a separate, refreshable copy for BU readers and puts an automatic row gate on that copy.

A Platform Operations member can query the published copy normally:

```sql
SELECT *
FROM system_tables_facade.published.billing__usage;
```

Unity Catalog checks every row against the caller's account-group assignment. The query needs no `WHERE` clause:

| Row's `workspace_id` | Result |
|---|---|
| `101` | returned |
| `102` | returned |
| `999` | hidden |
| `NULL` | hidden |

The group is not granted access to the original `system` table, so it cannot bypass this row gate through an accelerator-created grant.

## How it works

```text
Administrator records which account group owns which workspace IDs
        |
        v
Databricks system tables stay private
        |
        | refresh a separate copy for BU readers
        v
Published catalog — the only catalog the accelerator grants to BUs
        |
        | Unity Catalog automatically hides rows outside the group's IDs
        v
BU account group sees its own workspace rows only
```

The published catalog contains **materialized views**: stored, refreshable copies of supported system tables. The automatic row gate is a Unity Catalog **ABAC row-filter policy** attached to those copies.

The copies are not real-time data. They introduce refresh latency, storage use and refresh cost; see [Limitations](#limitations). The accelerator uses copies because it cannot modify Databricks-owned system tables, and ordinary views cannot carry ABAC policies directly.

## Four concepts to know

| Plain-language concept | Repository term | Meaning |
|---|---|---|
| **Original shared data** | **Source table** | A read-only table in Databricks' `system` catalog. The accelerator never grants this directly to BUs. |
| **Guarded copy for BU readers** | **Published table** | A materialized view in the separate **published catalog**. The code sometimes calls this catalog the **facade**. |
| **Who may see which workspaces** | **Consumer group** and **workspace assignment** | A Databricks account group and the workspace IDs for which it is responsible. |
| **Automatic row gate** | **ABAC policy** | A Unity Catalog rule that attaches a row filter to published tables. A **governed tag** is the controlled label that tells the policy where to apply. |

## Who does what?

Only the administrator changes the accelerator. BU groups read the guarded published tables. Temporary test identities prove that the same guard works for a real group member.

| Role | What it does |
|---|---|
| **Metastore administrator** | Plans, reviews and applies the published catalog, policies and grants. |
| **BU account group** | Reads named published tables; Unity Catalog hides rows outside its assigned workspace IDs. |
| **Representative service principal** | Temporarily joins one BU account group so `verify` can test that group's real access path through the SQL Statement Execution API. |

A service principal does **not** impersonate or assume the identity of a human user. It authenticates as itself. Its account-group membership makes it a representative for testing that group's access.

## What happens to every system table?

Every discovered system table receives one explicit handling mode:

1. **Workspace-scoped** — published with a mandatory workspace row filter.
2. **Account-shared** — published without workspace filtering only after an explicit configuration override and written rationale. A table with any discovered `workspace_id` column can never use this mode.
3. **Admin-only** — discovered and reported, but not published to BUs.
4. **Unavailable** — reported but not published because its columns could not be safely inspected.

Nothing is silently omitted or silently shared.

## What the accelerator creates

In the target metastore it creates:

1. one dedicated catalog and schema for published system-table data;
2. two account-level governed tags;
3. one SQL row-filter function generated from the configured group-to-workspace assignments;
4. one materialized view for each workspace-scoped or explicitly account-shared source;
5. governed tags on the published tables and each scoped `workspace_id` column;
6. one ABAC row-filter policy over the published schema; and
7. object-level grants on the named published tables.

Consumer groups receive `USE CATALOG`, `USE SCHEMA`, and `SELECT` on the named published tables only. They do not receive schema-wide `SELECT`, access to materialization backing objects, or grants on the `system` catalog.

## Configuration

Start with [`examples/config.example.json`](examples/config.example.json), but store the real configuration outside this public repository.

The important section is the group-to-workspace mapping:

```json
{
  "consumer_groups": [
    {
      "name": "bu_alpha_system_table_readers",
      "workspace_ids": ["1111111111111111"]
    },
    {
      "name": "bu_beta_system_table_readers",
      "workspace_ids": [
        "2222222222222222",
        "3333333333333333"
      ]
    }
  ],
  "trusted_principals": [
    "system_table_facade_admins",
    "system_table_facade_pipeline"
  ]
}
```

Use canonical decimal workspace IDs, not workspace display names. Display names can be reused after a workspace is deleted or recreated.

- `consumer_groups` are the account groups receiving filtered access.
- `trusted_principals` are narrowly scoped administrators or materialized-view run-as identities that need unfiltered access.
- `overrides` are exceptional, reviewed decisions such as publishing a genuinely account-global reference table.

The parser rejects unknown fields, duplicate JSON keys, unsafe identifiers, secret-shaped values, duplicate assignments within one group, overlap between consumer and trusted principals, and unsafe account-sharing overrides.

## Operator workflow

### 1. Install

Requirements:

- Python 3.11+
- Databricks CLI 0.292+
- a serverless SQL warehouse
- a Databricks profile for the administrator
- the Unity Catalog and governed-tag privileges listed in [Prerequisites](#prerequisites)

```bash
uv sync --frozen
. .venv/bin/activate
```

### 2. Generate a read-only plan

```bash
export DATABRICKS_WAREHOUSE_ID='<warehouse-id-kept-outside-git>'

abac-system-tables plan \
  --config /secure/path/config.json \
  --profile '<administrator-profile>' \
  --output /secure/path/plan.json
```

`plan` discovers system tables and the current published-catalog state. It does not change Unity Catalog.

The public-safe plan output is intentionally redacted. It shows:

- every source table and its handling mode;
- aggregate existing-object and direct-privilege counts;
- operation kinds in execution order; and
- hashed target references.

It does **not** expose SQL statements, principal names or grant targets. The summary is enough to detect unexpected scope and account-sharing decisions, but it is not a complete production privilege review. Inspect tenant-specific grant and target details through your organization's protected change-management process.

The output contains a `planDigest`. It binds the exact configuration, discovered sources, current objects and privileges, and generated SQL operations—even though those sensitive details are not printed in the public-safe summary.

### 3. Apply exactly that reviewed plan

```bash
abac-system-tables apply \
  --config /secure/path/config.json \
  --profile '<administrator-profile>' \
  --confirm '<planDigest-from-plan>' \
  --output /secure/path/apply-evidence.json
```

Apply re-runs discovery. If the sources, configuration or current privileges changed after planning, the digest no longer matches and apply stops.

For safety, every apply temporarily removes non-trusted access—including already-correct consumer grants—while materialized views, tags and policies are replaced. Consumer grants are restored only after every workspace-scoped table reports the expected effective ABAC policy. Plan a read interruption for each apply. A failed apply leaves consumers denied rather than reopening unverified access.

### 4. Verify with representative service principals

Create one temporary service principal for each BU test case, add it to exactly that BU's account group, and authenticate as the SP through a short-lived profile.

```bash
abac-system-tables verify \
  --config /secure/path/config.json \
  --scenarios /secure/path/verify.json \
  --warehouse-id "$DATABRICKS_WAREHOUSE_ID" \
  --output /secure/path/verify-evidence.json
```

A scenario can require:

- `scoped` — at least one permitted workspace is visible and zero null, unassigned or cross-BU rows are visible;
- `shared` — an approved account-shared table is readable; or
- `denied` — access fails with an authorization error, not merely a timeout or missing object.

Verification first confirms that `current_user()` and `session_user()` match the expected SP, that the SP belongs to the intended consumer group, and that it is not a trusted exemption.

See [`examples/verify.example.json`](examples/verify.example.json) and [short-lived service-principal testing](docs/obo-testing.md).

## Prerequisites

The deployer needs enough privilege to:

- read enabled system tables;
- create and manage the dedicated catalog and schema;
- create governed tags and assign them;
- create materialized views and SQL functions;
- create ABAC policies; and
- manage grants on the published hierarchy.

Production consumers must be Databricks **account groups** assigned to the relevant workspace. Do not use workspace-local groups for the policy configuration.

The published schema must be dedicated to this accelerator. Unexpected user-created tables block planning rather than being deleted.

## Safety properties

- Unknown, null and unmapped workspace IDs are denied.
- A source with a `workspace_id` column cannot be marked account-shared.
- Consumers never receive direct grants from this project on `system`.
- Consumers receive object-level `SELECT`, not schema-wide `SELECT`.
- Existing direct non-trusted catalog, schema and table privileges are revoked before replacement.
- Stale accelerator-managed materialized views are retired.
- Existing governed tags are reused only when their allowed values match exactly.
- Result rows, credentials and tenant identifiers are not written to normal plan/apply evidence.
- Partial or paginated verification evidence is rejected rather than treated as complete.

See [`SECURITY.md`](SECURITY.md) for the threat model and [`docs/operations.md`](docs/operations.md) for rollout and rollback guidance.

## Databricks bundle

[`databricks.yml`](databricks.yml) packages the Python wheel and contains no live profile, host or tenant ID.

```bash
databricks bundle validate --strict \
  -t validation \
  --profile '<administrator-profile>'
```

Bundle validation checks packaging only. It does not deploy governance. The explicit `apply --confirm <planDigest>` command is the mutation boundary.

## Public-repository safety

Never commit:

- Databricks profiles or workspace URLs;
- workspace, account, metastore, warehouse or principal IDs;
- OAuth secrets, PATs or private keys;
- production group-to-workspace configuration;
- raw query output; or
- connected plan/apply evidence.

Keep environment-specific desired state and evidence in a protected deployment repository or secret-backed pipeline.

## Limitations

- Materialized data is not real time. Refresh latency follows the configured schedule.
- Materialized views consume storage and refresh compute.
- Compatibility and refresh cost can vary by system table and cloud or region.
- Direct grants or broad roles on the original `system` catalog are outside this accelerator. Production verification must prove that consumers cannot bypass the published catalog.
- Governed-tag propagation can take several minutes.
- Every apply intentionally interrupts BU reads until all policy gates pass.
- Catalog/schema/table ownership and non-table objects such as functions or volumes remain operational governance responsibilities.
- A source whose metadata cannot be safely inspected remains unavailable rather than being guessed.

## Development

```bash
PYTHONPATH=src uv run --no-sync make check
git diff --check
```

The checks include formatting, lint, strict typing, 64 unit tests, coverage, package build, example parsing and secret scanning.
