# Migrate from v1 copied data to v2 direct ABAC

Version 1 created materialized copies of system tables. Version 2 applies governed tags and one ABAC policy directly to original `system` tables. The v2 parser rejects v1 configuration.

## Configuration change

Replace:

```json
"version": 1,
"facade": {
  "catalog": "system_tables_facade",
  "schema": "published",
  "refresh_every_hours": 24
}
```

with:

```json
"version": 2,
"governance": {
  "catalog": "system_tables_governance",
  "schema": "abac"
}
```

Keep tag keys, consumer-group assignments, trusted principals, and reviewed overrides unless a separately approved migration changes them.

The governance schema stores only the UDF and control-plane state; it never stores copied system rows.

## Pre-release v2 control-table lease migration

An environment that ran the early v2 draft before the deployment lease was added must add the two nullable lease columns before running the current planner:

```sql
ALTER TABLE <governance-catalog>.<governance-schema>.deployment_state
ADD COLUMNS (lease_token STRING, lease_acquired_at TIMESTAMP);
```

Run this once through the normal governance change process. Do not execute it blindly if the columns already exist. Fresh v2 installations create both columns automatically.

## Policy ownership preflight

Version 2 owns a catalog policy named `workspace_scope` on `CATALOG system`. Planning blocks if that fixed name already exists without compatible v2 `deployment_state`; it never silently replaces a foreign policy.

Inventory existing catalog policies before migration. The temporary validation policy `direct_catalog_workspace_scope_test` must be explicitly dropped before v2 apply, or replaced through a separately reviewed ownership-adoption procedure. A differently named policy can coexist only if it does not resolve as another row filter on the tagged targets: the effective-policy gate requires exactly `workspace_scope` and stops before managed grants if a conflict appears.

## Safe migration order

1. Inventory the v1 materialized-view refresh pipeline and every refresh/run-as identity.
2. Add those identities temporarily to v2 `trusted_principals` **before** applying direct tags or policy. Otherwise the new direct policy can filter the refresh input and permanently write incomplete copied rollback data.
3. Run and verify a successful v1 refresh while those identities are trusted. Confirm the copied facade still contains the expected cross-workspace administrator view.
4. Only after that successful refresh, preserve the v1 facade as the rollback path.
5. Create the v2 configuration outside Git and run a read-only plan.
6. Audit existing direct `system` readers because v2 default-denies unconfigured readers of tagged tables.
7. Complete the policy-ownership preflight above, including explicit removal/adoption of temporary validation policies.
8. Apply v2 direct tags, policy, and grants.
9. Verify direct `system.<schema>.<table>` queries with representative SPs for every BU.
10. Confirm cross-workspace rows are absent and trusted administrators retain intended access.
11. Re-run and verify the v1 refresh during coexistence; keep its run-as identity trusted for as long as v1 remains a rollback path.
12. Operate through v2 for an agreed observation period.
13. Plan v1 cleanup and removal of the temporary run-as exemption as separate reviewed changes.

## Cleanup is intentionally not automatic

The v2 accelerator does not drop the old facade catalog, materialized views, refresh pipelines, backing/event-log tables, old UDF, old ABAC policy, old governed tags, or grants. Automatic cleanup could remove a rollback path or delete objects not exclusively owned by the accelerator.

Before cleanup, inventory ownership, dependencies, active queries, grants, backing pipelines, and governed-tag references. Revoke old consumer access first, wait for confirmation, then remove copied objects through the organization's destructive-change process.
