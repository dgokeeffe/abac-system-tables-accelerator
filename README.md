# Databricks ABAC system tables accelerator

A public-safe reference implementation for publishing Databricks system-table metadata to business units without granting metastore-wide row access.

The accelerator discovers enabled `system` tables, materialises publishable sources into an isolated Unity Catalog facade, classifies every source, tags workspace-scoped materialized views, and applies a single schema-scoped ABAC row-filter policy. An account group can see a row only when its configured workspace assignment matches that row's `workspace_id`.

> **Status:** alpha reference accelerator. Always run `plan`, review the dispositions, and test with representative principals before production use.

## Security model

- `workspace_id STRING` sources default to `workspace_scoped`.
- Sources without that exact scope column default to `admin_only`.
- Sources whose columns are not visible are reported as `unavailable`.
- `account_shared` requires an explicit per-table override, a human-readable rationale, and no discovered `workspace_id` column. A workspace-scoped source can never be widened to account-shared.
- Null, unknown, and unassigned workspace IDs fail closed in the policy UDF.
- Consumer groups receive `USE CATALOG`, `USE SCHEMA`, and object-level `SELECT` only on named facade materialized views. They never receive schema-wide `SELECT`, so internal backing/event-log or newly created objects are not readable. This project never grants on `system`.
- Governed tags are a security boundary. Restrict `ASSIGN`/`APPLY TAG` to governance automation and admins.
- Ordinary views cannot directly carry ABAC policies, so publishable sources are standalone materialized views.
- The materialized-view run-as principal is trusted and explicitly exempted. Keep that exemption narrow.
- ABAC requires serverless SQL or compatible Databricks Runtime. This implementation uses a SQL warehouse and Statement Execution API.

See [SECURITY.md](SECURITY.md) for threat assumptions and [docs/operations.md](docs/operations.md) for the rollout sequence.

## What is created

1. A facade catalog and schema.
2. Two account-level governed tags (after `SHOW`/`DESCRIBE` preflight).
3. One SQL UDF generated from account-group/workspace assignments.
4. One standalone materialized view for each `workspace_scoped` or explicitly `account_shared` source.
5. Table tags on all published objects and a column tag on each scoped `workspace_id`.
6. One schema-scoped ABAC row-filter policy.
7. Facade-only grants for configured consumer account groups and explicitly trusted principals.

`admin_only` and `unavailable` sources are included in the plan but are not copied or granted.

## Prerequisites

- Python 3.11+
- Databricks CLI 0.292+ and `databricks-sdk`
- Serverless SQL warehouse
- Unity Catalog metastore administrator or delegated privileges:
  - create/manage the facade catalog and schema;
  - create governed tags and assign them;
  - read enabled system tables;
  - create materialized views, SQL functions, policies, and grants.
- Account groups already provisioned and assigned to the workspace. Do not use workspace-local groups in production.

Never commit profiles, hosts, IDs, tokens, service-principal secrets, or live outputs. Environment-specific config should be stored in a protected deployment repository or secret-backed pipeline.

## Install

```bash
uv sync --locked
. .venv/bin/activate
```

## Configure

Copy `examples/config.example.json` outside the repository and replace placeholders. Workspace display names are not accepted because they can be reused; use canonical decimal workspace IDs.

The parser rejects unknown fields, duplicate JSON keys, unsafe identifiers/principals, secret-shaped data, duplicate assignments within a group, consumer/trusted principal-name overlap, and unsafe account-sharing overrides. A principal that belongs to multiple configured consumer groups receives the union of those groups' workspace IDs; assigning the same workspace to different groups is therefore allowed and explicit. The facade schema is dedicated to this accelerator: an unrelated object blocks planning rather than being deleted.

## Plan (read-only)

`plan` reads only `system.information_schema` through Statement Execution. It does not mutate Unity Catalog.

```bash
export DATABRICKS_WAREHOUSE_ID='<set outside Git>'
abac-system-tables plan \
  --config /secure/path/config.json \
  --profile '<explicit-admin-profile>' \
  --output /secure/path/plan.json
```

The output is row-data-free and redacts tenant targets as hashes. Review every source disposition, existing facade object count, grant count, and planned reconciliation. The `planDigest` binds configuration, discovered sources, current facade objects/grants, and exact SQL steps; it is the apply confirmation token.

## Apply

```bash
abac-system-tables apply \
  --config /secure/path/config.json \
  --profile '<explicit-admin-profile>' \
  --confirm '<planDigest-from-plan>' \
  --output /secure/path/apply-evidence.json
```

Apply re-discovers sources and facade state, validates `current_user() = session_user()`, requires the exact reviewed plan digest, revokes every discovered non-trusted direct catalog/schema/table privilege (including currently desired consumer grants and tag/management authority), retires stale tagged materialized views, and restores only the declared least-privilege consumer grants at the end. This intentionally causes a fail-closed read interruption on every apply. Before any grant is restored, it boundedly polls `SHOW EFFECTIVE POLICIES` for every workspace-scoped materialized view. Existing governed tags are retained only when their allowed-value sets match exactly. A failed apply intentionally leaves consumers denied until an administrator diagnoses and safely reruns or rolls back.

## Verify as representative service principals

Each scenario profile **authenticates as the service principal itself**. The scenario's `expected_identity` must exactly match both `current_user()` and `session_user()`. The accelerator does not claim or attempt unsupported arbitrary-user impersonation.

```bash
abac-system-tables verify \
  --config /secure/path/config.json \
  --scenarios /secure/path/verify.json \
  --warehouse-id "$DATABRICKS_WAREHOUSE_ID" \
  --output /secure/path/verify-evidence.json
```

Each scenario names one configured consumer group. Verification proves the identity belongs to that group and is neither a trusted identity nor a member of a trusted group. A `scoped` check uses a server-side aggregate, requires non-empty permitted scope, and requires zero null/unassigned/cross-BU rows. A `shared` check must succeed. A `denied` check passes only on an authorization-specific error (not timeout, cancellation, or missing object) and should include direct `system` source access. Result rows are never written to evidence.

For short-lived on-behalf-of tokens, see [docs/obo-testing.md](docs/obo-testing.md) and `scripts/create_obo_token_file.sh`.

## Databricks bundle

`databricks.yml` packages the wheel and contains generic validation variables only—no profile, host, or live ID. Validate using an explicitly chosen local profile:

```bash
databricks bundle validate --strict -t validation --profile '<explicit-profile>'
```

The bundle does not deploy governance automatically; the confirmed CLI `apply` flow is the mutation boundary.

## Development

```bash
make check
git diff --check
```

`make check` runs formatting checks, lint, strict typing, tests with coverage, package build, example parsing, and a repository secret-pattern scan.

## Limitations

- Standalone materialized-view compatibility and refresh cost vary by system table and cloud/region. Test each `workspace_scoped` and `account_shared` source before broad rollout.
- Materialized data has refresh latency and must be lifecycle-managed.
- Existing grants on `system` are outside this accelerator. Verification must prove representative principals cannot use that bypass.
- Tag propagation can take several minutes; connected verification should retry only within a bounded rollout window.
- Schema drift that hides columns yields `unavailable`; a formerly scoped source cannot be silently widened.
