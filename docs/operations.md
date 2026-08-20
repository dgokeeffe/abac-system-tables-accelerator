# Operations guide

## Rollout

1. Create BU account groups, trusted governance administrators, and representative test service principals.
2. Inventory existing readers of the target system tables. The direct catalog policy default-denies tagged rows for unconfigured, non-trusted readers.
3. Resolve active workspaces to canonical IDs; do not use display names.
4. Put the v2 configuration outside Git and run `plan` with an explicit administrator profile.
5. Review every workspace-scoped/account-shared/admin-only/unavailable decision, stale protected tags, prior managed-grant count, and operation sequence.
6. Apply the exact `planDigest` in a change window. Prior managed `SELECT` grants are temporarily revoked.
7. Confirm every workspace-scoped table reports `workspace_scope` as its single effective row filter.
8. Inspect direct table grants and confirm admin-only/unavailable tables have no accelerator-managed consumer grant.
9. Verify each BU through a representative SP using Statement Execution.
10. Revoke temporary credentials immediately and retain only redacted evidence.

## Apply sequence and recovery

Apply enforces one writer per governance schema with a conditional lease in `deployment_state`. The winner proves its unique runtime token before any revoke, tag, UDF, or policy mutation and renews the lease before every later plan step. A loser fails before governance mutation. Ordinary success or failure releases only the caller's token; a process that dies is recoverable after the bounded 30-minute stale timeout. Do not run an individual blocking SQL operation longer than the lease timeout.

The governance schema stores no system rows, but it is a privileged security boundary because its control rows authorize later revocations. Only the deployment identity and trusted governance administrators may write it. `managed_grants` is a control-plane manifest:

- `PENDING` means the desired tuple was recorded after `deployment_state.pending_config_digest` was set and before grant execution.
- `ACTIVE` means all direct grants completed for `deployment_state.last_successful_config_digest`. During the narrow recovery window after grant activation but before the final state update, ACTIVE rows may instead match `pending_config_digest`; the next apply validates and revokes them before retrying.

Before generating a revoke, planning requires each row's digest to match the corresponding pending/successful deployment digest and requires its target to be both discovered and tagged by this accelerator. Every valid prior `PENDING` and `ACTIVE` tuple is revoked before the manifest is cleared. Therefore a failed grant run is recoverable by planning and applying again.

A failure before grants leaves managed readers closed. A failure after some grants leaves `PENDING` rows that the next apply revokes. Do not manually delete the manifest to bypass recovery.

`deployment_state` contains a required singleton with state version, tag keys, fixed `system` policy scope/name, pending config digest, last successful config digest, and the renewable lease token/timestamp. Missing, partial, malformed, or incompatible state blocks planning. Use a separately designed migration rather than editing this row.

## Stale tags

Apply never runs `UNSET TAG` on system tables or columns. Removing a table from desired state closes its manifest-owned `SELECT`, but existing governed tags stay in place. The redacted plan reports them by type: stale `workspace_scoped` tags remain filtered and fail closed; stale `account_shared` tags have no row filter and therefore depend on managed-grant closure plus a separate audit of external grants. Planning blocks if the accelerator's workspace-column tag appears on any column other than `workspace_id`.

Manual tag removal can unfilter unrelated pre-existing readers. Treat it as a separate change after auditing all grants, policies, and callers.

## External grants

The shared `system` catalog can contain grants not created by this accelerator. They are intentionally not revoked. For tagged workspace-scoped tables, the policy still default-denies unconfigured non-trusted readers. Account-shared tables have no row filter, so external grants require separate audit.

## Failure and rollback

Stop on the first failure and inspect persisted state. Do not blindly remove tags or the catalog policy: doing so can reopen unfiltered access.

Safe emergency closure is to revoke the affected consumer table `SELECT` grants while leaving tags and policy intact. Rollback of the direct policy, governed tags, governance state, or old v1 objects is destructive and requires an explicit reviewed procedure. During v1-to-v2 migration, follow the run-as coexistence and policy-ownership steps in [the migration guide](migration-v1-to-v2.md).

## Drift

Re-run plan when system schemas, source columns, workspace assignments, consumer/trusted groups, or grants change. A source with unavailable columns receives no new access. A table with any `workspace_id` cannot be widened to account-shared.

## Evidence

Retain only config/plan digests, disposition counts, standard system-table names, hashed statement references, state counts, and verification pass/fail summaries. Keep real principal/workspace IDs and raw platform output outside Git.
