# Security policy

## Reporting

Report suspected vulnerabilities privately to the repository maintainers. Do not include credentials, tenant data, workspace URLs, identifiers, or live query output in public issues.

## Threat model

This accelerator assumes the deployer is a trusted Unity Catalog governance administrator and that configured consumer groups are account groups managed by the organization's identity lifecycle. It treats governed tags, group membership, direct grants, the materialized-view run-as identity, and the facade owner as security boundaries.

The primary threats are:

- a consumer bypassing the facade through a direct `system` grant;
- an unscoped or mistyped table being published;
- null, unknown, or reused workspace metadata widening access;
- unsafe tag reassignment disabling the policy;
- a trusted exemption being granted to a consumer;
- SQL injection through desired state or discovered metadata;
- credentials or tenant metadata being committed or logged;
- a materialized refresh permanently applying a source policy to copied data;
- stale materialized data or system-table schema drift producing misleading results.

## Controls

- Strict JSON parsing rejects duplicates, unknown fields, unsafe values, and secret patterns.
- Workspace display names are not accepted; only decimal IDs are used.
- Missing/non-STRING workspace scope defaults to admin-only.
- Publishing account-global data is an explicit, rationale-bearing exception.
- SQL identifiers and principals use narrow allowlists; literals are escaped.
- Consumer and trusted principal sets cannot overlap.
- The generated UDF is fail closed and the ABAC policy matches governed table/column tags.
- Only facade grants are generated. Consumers receive object-level `SELECT` on named published materialized views, never schema-wide `SELECT`; trusted principals are the only schema-wide readers.
- Every direct catalog/schema/table privilege held by a non-trusted principal—including read, tag, create, and management authority—is discovered and revoked before replacement; only declared navigation and object-level read grants are restored.
- Apply requires a digest confirmation and validates the session identity.
- Normal output contains no rows, credentials, tenant IDs, or unredacted statement IDs.
- Verification runs as representative principals and checks both row scope and denied bypasses.

## Operational requirements

Restrict tag assignment, policy management, facade ownership, and pipeline run-as privileges. Review effective policies and grants after every change. Revoke and delete test credentials immediately. Store raw connected evidence outside Git with access controls and retention. Never exempt broad user groups from policy enforcement.

## Unsupported claims

A Databricks profile or token authenticates one identity. This accelerator does not impersonate arbitrary users. A representative service principal is valid only as a test fixture for the account groups it actually belongs to.
