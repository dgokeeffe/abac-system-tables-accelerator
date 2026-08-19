# ABAC system tables accelerator

The problem is metastore-wide system tables: business units that operate only a subset of workspaces should not receive metastore-wide rows. The accelerator must let a metastore administrator publish a governed facade in which account groups see only rows for configured workspace IDs.

## Bounded outcome for this build

Create a public-safe Python/Databricks bundle repository that:

- validates a strict JSON desired-state file;
- discovers every enabled `system` table at deployment time;
- classifies tables with a validated `workspace_id` column as workspace-scoped;
- treats tables without that column as admin-only unless an explicit safe strategy is configured;
- materialises workspace-scoped sources into a dedicated Unity Catalog schema, because ABAC cannot be attached directly to ordinary views and system tables are system-owned;
- applies governed table/column tags and one schema-scoped ABAC row-filter policy;
- generates group-aware policy logic from config, with deny-by-default handling for null, unknown, and unmapped workspace IDs;
- grants consumers access only to the facade, never the `system` sources;
- provides a Statement Execution API test harness that authenticates as representative service principals rather than claiming unsupported arbitrary-user impersonation;
- emits redacted plans/evidence and supports dry-run before mutation.

Account-global system tables are still in scope as discovered objects, but default to `admin_only`. A configuration may explicitly publish one only after a human documents why its rows are safe for every configured BU. Nothing is silently omitted or silently shared.

## Acceptance contract

1. Invalid, ambiguous, duplicate, or secret-shaped config is rejected before API access.
2. Identifiers are strictly validated and safely quoted; SQL generation cannot widen scope through injection.
3. Every discovered source receives one explicit disposition: `workspace_scoped`, `account_shared`, `admin_only`, or `unavailable`.
4. Workspace-scoped facade objects have a directly tagged `workspace_id` column and match one ABAC row-filter policy.
5. The policy applies to configured consumer groups, exempts only configured trusted admins/run-as principals, and returns false unless a configured account-group/workspace assignment matches.
6. No BU grant is made on `system` catalog schemas or tables.
7. Plan mode is deterministic and mutation-free. Apply is ordered, idempotent where supported, records statement IDs, and redacts tenant values from default console output.
8. Representative service principals can query allowed rows and cannot observe rows for another BU, unassigned rows, admin-only objects, or source objects.
9. The repository contains no credentials or live tenant identifiers and passes local tests, static checks, bundle validation, and a secret scan.
10. Connected evidence is kept outside Git and summarised here without tenant identifiers.

## Impact map and security invariants

The change creates a catalog/schema, materialized facade objects, governed tag assignments, a policy UDF and ABAC policy, grants, and optional test identities/groups. It affects UC governance, SQL warehouse usage, system-table consumers, and IAM test fixtures.

Invariants:

- deny by default;
- session identity and account-group membership are the only caller attributes trusted by policy logic;
- only source `workspace_id` values determine row scope;
- no client-side filter is a security boundary;
- tags are a security boundary and only deployment/admin identities may assign them;
- configured admins and pipeline run-as principals are explicit, minimal exemptions;
- direct grants and alternate paths cannot bypass the facade;
- schema/capability drift fails closed;
- secrets and tenant metadata never enter Git or normal logs.

## Product facts verified from official documentation

- ABAC row filters require serverless compute or Databricks Runtime 16.4+.
- Policies may be scoped to catalogs, schemas, or tables and use governed tags to match tables/columns.
- Consumers still require ordinary `SELECT`; row-filter policies restrict but do not grant.
- Ordinary views cannot carry ABAC policies. Policies on base tables are respected through views using the session user's identity.
- Materialized views and streaming tables are supported ABAC targets. A pipeline refresh uses the pipeline run-as identity, which must be exempt from source policies to avoid permanently filtered output.
- One distinct row filter may resolve per table/user; conflicting filters fail closed.
- Policy UDFs may use a small lookup table, but this design generates explicit group predicates to avoid dynamic group-name ambiguity and to keep configuration reviewable.
- Tag changes can take several minutes to propagate.

Sources:

- https://docs.databricks.com/aws/en/data-governance/unity-catalog/abac/core-concepts
- https://docs.databricks.com/aws/en/data-governance/unity-catalog/abac/policies
- https://docs.databricks.com/aws/en/data-governance/unity-catalog/abac/requirements
- https://docs.databricks.com/aws/en/data-governance/unity-catalog/abac/policy-evaluation
- https://docs.databricks.com/aws/en/sql/language-manual/sql-ref-syntax-ddl-create-policy

## Live discovery, redacted

The authorised test metastore exposes multiple enabled system schemas. A metadata query found both workspace-scoped and account-global tables. The three intended active test workspaces resolve uniquely only when lifecycle status is included; older deleted workspaces reuse the same display names. Therefore config must use canonical workspace IDs, and helper resolution must reject names that are absent or non-unique among active records.

## Verification plan

Offline: config parser and semantic validation; SQL golden tests; injection/malformed/duplicate/secret cases; deterministic/idempotent plans; statement lifecycle and redaction tests; `ruff`, `mypy`, `pytest`, bundle strict validation, secret scan, and `git diff --check`.

Connected: dry-run discovery; create isolated facade; inspect effective policies/tags/grants; run positive/negative/admin/source-bypass matrix as short-lived representative service principals through Statement Execution API; delete or revoke temporary credentials immediately; keep raw evidence outside Git; rerun after fixes and independent review.

## Connected verification (redacted)

An isolated deployment was completed through the Statement Execution API. Discovery assigned an explicit disposition to all 40 enabled system tables: 35 workspace-scoped, one reviewed account-shared reference table, and four account-global/admin-only tables. The final full apply completed 379 ordered steps successfully, including reconciliation of all direct non-trusted facade privileges and 35 effective-policy propagation gates before least-privilege grants were restored.

Three account-group-backed representative service principals authenticated as themselves through short-lived OAuth M2M credentials. Each principal's aggregate verification returned exactly one assigned workspace scope and zero disallowed rows from the workspace inventory facade; each could read the reviewed account-shared reference. Consumer groups have `USE SCHEMA` plus direct `SELECT` only on the 36 named facade materialized views. They have no schema-wide `SELECT`, and materialization backing/event-log objects have no consumer grants. Temporary OAuth secrets were revoked immediately after testing; controlled test groups and service principals remain for repeatable regression testing.

A direct-source-denial assertion could not be accepted in this sandbox because its broad `account users` group carries the account-admin role, so every representative service principal inherits direct system-table access independently of the accelerator. This environment limitation is disclosed rather than reported as a pass. Production acceptance must audit and remove direct `system` grants/roles and run the repository's authorization-specific denied-source checks in a least-privilege tenant.

Offline evidence: `make check` passes 64 tests with 91% coverage, strict Ruff and mypy, package builds, example parsing, and secret scan. `databricks bundle validate --strict` and `git diff --check` pass. The public repository is https://github.com/dgokeeffe/abac-system-tables-accelerator and its GitHub Actions `ci` workflow passes from the committed public-PyPI lock. Raw connected evidence and tenant identifiers remain outside Git.

## Handoff

What changed or was learned: a complete public-safe package, bundle, examples, CI, operations/security docs, config validator, planner, apply engine, and representative-principal verifier now exist. Live metadata confirmed mixed workspace/account scope and reused workspace display names. Standalone materialized views work for every workspace-scoped source in the test metastore; object-level grants are required because Databricks creates untagged backing tables in the same schema.

Still uncertain: direct-source denial cannot be demonstrated in the current sandbox because of its broad account-admin inheritance. The four account-global tables remain admin-only except for the single reviewed price reference. Every apply deliberately revokes and later restores even correct consumer grants to close replacement/tag propagation windows, so operators must plan a temporary read interruption; facade ownership and non-table authority remain operational governance responsibilities.

Next question: run the denied-source matrix in a production-like least-privilege tenant before promotion, then decide whether the retained regression identities should be deleted or owned as permanent test fixtures.
