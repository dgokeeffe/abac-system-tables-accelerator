from __future__ import annotations

import json

import pytest

from abac_system_tables import sql
from abac_system_tables.client import StatementError, StatementResult
from abac_system_tables.config import ConfigError, loads_config
from abac_system_tables.plan import (
    CatalogPolicy,
    DeploymentState,
    ExternalSelect,
    GovernanceState,
    ManagedColumnTag,
    ManagedGrant,
    ManagedTableTag,
    SourceTable,
    build_plan,
    classify,
    discover,
    discover_governance_state,
    parse_discovery,
)
from tests.helpers import FakeClient, valid_config_data, valid_config_text


def config():
    return loads_config(valid_config_text())


def sources() -> tuple[SourceTable, ...]:
    return (
        SourceTable("access", "audit", "MANAGED", 17, "STRING"),
        SourceTable("billing", "list_prices", "MANAGED", 8, None),
        SourceTable("compute", "hidden", "MANAGED", 0, None),
    )


def test_parse_discovery_and_describe_fallback() -> None:
    columns = ("table_schema", "table_name", "table_type", "column_count", "workspace_id_type")
    parsed = parse_discovery(columns, (("access", "audit", "MANAGED", "17", "string"),))
    assert parsed[0].workspace_id_type == "STRING"
    with pytest.raises(ConfigError, match="unexpected discovery schema"):
        parse_discovery(("wrong",), ())

    def handler(statement: str, _rows: bool) -> StatementResult:
        if statement.startswith("WITH source_tables"):
            return StatementResult(
                "i", "SUCCEEDED", columns, (("alert", "alerts", "MANAGED", "0", None),)
            )
        return StatementResult(
            "d",
            "SUCCEEDED",
            ("col_name", "data_type", "comment"),
            (("account_id", "string", ""), ("workspace_id", "string", "")),
        )

    assert discover(FakeClient(handler))[0].workspace_id_type == "STRING"

    def denied(statement: str, rows: bool) -> StatementResult:
        if statement.startswith("WITH source_tables"):
            return handler(statement, rows)
        raise StatementError("denied", error_code="PERMISSION_DENIED")

    assert discover(FakeClient(denied))[0].column_count == 0


def test_classification_and_account_shared_guard() -> None:
    assert [item.disposition for item in classify(config(), sources())] == [
        "workspace_scoped",
        "admin_only",
        "unavailable",
    ]
    data = valid_config_data()
    data["overrides"] = [
        {
            "source": "system.billing.list_prices",
            "disposition": "account_shared",
            "rationale": "Account-global public price reference safe for every group.",
        }
    ]
    assert classify(loads_config(json.dumps(data)), sources())[1].disposition == "account_shared"
    data["overrides"][0]["source"] = "system.access.audit"
    with pytest.raises(ConfigError, match="cannot be account_shared"):
        classify(loads_config(json.dumps(data)), sources())


def compatible_state(*grants: ManagedGrant) -> GovernanceState:
    pending = next((grant.config_digest for grant in grants if grant.status == "PENDING"), None)
    active = next((grant.config_digest for grant in grants if grant.status == "ACTIVE"), "a" * 64)
    tags = tuple(
        ManagedTableTag(
            grant.schema,
            grant.table,
            "account_shared" if grant.table == "list_prices" else "workspace_scoped",
        )
        for grant in grants
    )
    column_tags = tuple(
        ManagedColumnTag(grant.schema, grant.table, "workspace_id", "")
        for grant in grants
        if grant.table != "list_prices"
    )
    return GovernanceState(
        deployment=DeploymentState(
            2,
            "system_table_scope",
            "workspace_scope_column",
            "system",
            "workspace_scope",
            active,
            pending,
        ),
        grants=grants,
        table_tags=tags,
        column_tags=column_tags,
        catalog_policies=(CatalogPolicy("workspace_scope", "ROW_FILTER"),),
    )


def test_direct_plan_orders_recovery_policy_gates_and_grants() -> None:
    old = ManagedGrant("removed_group", "access", "audit", "ACTIVE", "a" * 64)
    plan = build_plan(config(), sources(), compatible_state(old))
    kinds = [step.kind for step in plan.steps]
    assert kinds.index("initialize_deployment_state") < kinds.index("acquire_deployment_lock")
    assert kinds.index("acquire_deployment_lock") < kinds.index("revoke_prior_managed_select")
    assert kinds.index("revoke_prior_managed_select") < kinds.index("clear_managed_grant_state")
    assert kinds.index("create_catalog_policy") < kinds.index("set_direct_workspace_column_tag")
    assert kinds.index("set_direct_workspace_column_tag") < kinds.index("set_direct_table_tag")
    assert kinds.index("verify_effective_policy") < kinds.index("set_pending_deployment_state")
    assert kinds.index("set_pending_deployment_state") < kinds.index(
        "record_pending_managed_grants"
    )
    assert kinds.index("record_pending_managed_grants") < kinds.index("grant_direct_select")
    assert kinds.index("grant_direct_select") < kinds.index("activate_managed_grants")
    assert kinds[-1] == "upsert_deployment_state"
    generated = "\n".join(step.statement.upper() for step in plan.steps)
    assert "MATERIALIZED VIEW" not in generated and "SCHEDULE EVERY" not in generated
    assert "ON CATALOG SYSTEM" in generated


def test_pending_recovery_and_removed_account_shared_grant_are_revoked() -> None:
    pending = ManagedGrant("retired_group", "billing", "list_prices", "PENDING", "b" * 64)
    data = valid_config_data()
    data["overrides"] = [
        {
            "source": "system.billing.list_prices",
            "disposition": "account_shared",
            "rationale": "Account-global public price reference safe for every group.",
        }
    ]
    plan = build_plan(loads_config(json.dumps(data)), sources(), compatible_state(pending))
    revokes = [step.statement for step in plan.steps if step.kind == "revoke_prior_managed_select"]
    assert revokes == [
        "REVOKE SELECT ON TABLE `system`.`billing`.`list_prices` FROM `retired_group`"
    ]


def test_external_grants_are_preserved_and_not_claimed_by_manifest() -> None:
    external = ExternalSelect("bu_alpha", "access", "audit")
    plan = build_plan(config(), sources(), GovernanceState(external_selects=(external,)))
    statements = "\n".join(step.statement for step in plan.steps)
    assert "REVOKE SELECT ON TABLE `system`.`access`.`audit` FROM `bu_alpha`" not in statements
    assert "GRANT SELECT ON TABLE `system`.`access`.`audit` TO `bu_alpha`" not in statements
    assert plan.redacted()["preservedExternalSelectCount"] == 1


def test_managed_grant_is_not_reported_as_preserved_external_access() -> None:
    managed = ManagedGrant("bu_alpha", "access", "audit", "ACTIVE", "a" * 64)
    state = compatible_state(managed)
    state = GovernanceState(
        deployment=state.deployment,
        grants=state.grants,
        external_selects=(ExternalSelect("bu_alpha", "access", "audit"),),
        table_tags=state.table_tags,
        column_tags=state.column_tags,
        catalog_policies=state.catalog_policies,
    )
    plan = build_plan(config(), sources(), state)
    assert plan.redacted()["preservedExternalSelectCount"] == 0


def test_admin_only_and_unavailable_receive_no_tag_or_grant() -> None:
    plan = build_plan(config(), sources(), GovernanceState())
    generated = "\n".join(step.statement for step in plan.steps)
    assert "`system`.`billing`.`list_prices`" not in generated
    assert "`system`.`compute`.`hidden`" not in generated
    assert "`system`.`access`.`audit`" in generated


def test_stale_direct_tags_remain_reported_and_fail_closed() -> None:
    state = GovernanceState(
        table_tags=(ManagedTableTag("billing", "list_prices", "workspace_scoped"),)
    )
    plan = build_plan(config(), sources(), state)
    assert plan.stale_workspace_scoped_sources == ("system.billing.list_prices",)
    assert "fail-closed" in plan.redacted()["staleWorkspaceScopedAction"]
    assert not any("UNSET TAG" in step.statement for step in plan.steps)


def test_plan_digest_binds_config_sources_and_persisted_state_and_redacts() -> None:
    first = build_plan(config(), sources(), GovernanceState())
    second = build_plan(
        config(),
        sources(),
        compatible_state(ManagedGrant("old", "access", "audit", "ACTIVE", "a" * 64)),
    )
    assert first.digest != second.digest
    output = json.dumps(first.redacted())
    assert "bu_alpha" not in output and '"111"' not in output
    assert '"target": "governance_catalog"' not in output


def test_incompatible_deployment_state_blocks() -> None:
    bad = GovernanceState(
        deployment=DeploymentState(
            2, "other_tag", "workspace_scope_column", "system", "workspace_scope", None, None
        )
    )
    with pytest.raises(ConfigError, match="immutable deployment_state"):
        build_plan(config(), sources(), bad)


def test_discover_governance_state_parses_active_and_pending_rows() -> None:
    cfg = config()

    def handler(statement: str, _rows: bool) -> StatementResult:
        if statement == sql.catalog_policies_sql():
            return StatementResult(
                "p",
                "SUCCEEDED",
                ("Policy Name", "Policy Type"),
                (("workspace_scope", "ROW_FILTER"),),
            )
        if "table_tags" in statement:
            return StatementResult(
                "tt",
                "SUCCEEDED",
                ("schema_name", "table_name", "tag_value"),
                (("access", "audit", "workspace_scoped"),),
            )
        if "column_tags" in statement:
            return StatementResult(
                "ct",
                "SUCCEEDED",
                ("schema_name", "table_name", "column_name", "tag_value"),
                (("access", "audit", "workspace_id", ""),),
            )
        if "table_privileges" in statement:
            return StatementResult("eg", "SUCCEEDED", ("grantee", "table_schema", "table_name"), ())
        if "table_name IN" in statement:
            return StatementResult(
                "st",
                "SUCCEEDED",
                ("table_name",),
                ((sql.DEPLOYMENT_STATE_TABLE,), (sql.MANAGED_GRANTS_TABLE,)),
            )
        if "FROM `governance_catalog`.`system_tables_abac`.`deployment_state`" in statement:
            return StatementResult(
                "ds",
                "SUCCEEDED",
                (
                    "singleton",
                    "state_version",
                    "table_tag_key",
                    "workspace_column_tag_key",
                    "policy_scope",
                    "policy_name",
                    "last_successful_config_digest",
                    "pending_config_digest",
                    "lease_token",
                    "lease_acquired_at",
                ),
                (
                    (
                        "system_tables_abac",
                        "2",
                        "system_table_scope",
                        "workspace_scope_column",
                        "system",
                        "workspace_scope",
                        "a" * 64,
                        "b" * 64,
                        None,
                        None,
                    ),
                ),
            )
        return StatementResult(
            "mg",
            "SUCCEEDED",
            ("principal", "table_schema", "table_name", "status", "config_digest"),
            (("old", "access", "audit", "PENDING", "b" * 64),),
        )

    state = discover_governance_state(FakeClient(handler), cfg)
    assert state.deployment is not None and state.deployment.state_version == 2
    assert state.grants[0].status == "PENDING"
    assert state.table_tags[0].full_name == "system.access.audit"


def test_partial_control_state_blocks() -> None:
    cfg = config()

    def handler(statement: str, _rows: bool) -> StatementResult:
        if statement == sql.catalog_policies_sql():
            return StatementResult("p", "SUCCEEDED", ("Policy Name", "Policy Type"), ())
        if "table_tags" in statement:
            return StatementResult("t", "SUCCEEDED", ("schema_name", "table_name", "tag_value"), ())
        if "column_tags" in statement:
            return StatementResult(
                "c", "SUCCEEDED", ("schema_name", "table_name", "column_name", "tag_value"), ()
            )
        if "table_privileges" in statement:
            return StatementResult("e", "SUCCEEDED", ("grantee", "table_schema", "table_name"), ())
        return StatementResult("s", "SUCCEEDED", ("table_name",), ((sql.MANAGED_GRANTS_TABLE,),))

    with pytest.raises(ConfigError, match="partial"):
        discover_governance_state(FakeClient(handler), cfg)


def test_complete_control_tables_with_empty_deployment_state_blocks() -> None:
    cfg = config()

    def handler(statement: str, _rows: bool) -> StatementResult:
        if statement == sql.catalog_policies_sql():
            return StatementResult("p", "SUCCEEDED", ("Policy Name", "Policy Type"), ())
        if "table_tags" in statement:
            return StatementResult("t", "SUCCEEDED", ("schema_name", "table_name", "tag_value"), ())
        if "column_tags" in statement:
            return StatementResult(
                "c", "SUCCEEDED", ("schema_name", "table_name", "column_name", "tag_value"), ()
            )
        if "table_privileges" in statement:
            return StatementResult("e", "SUCCEEDED", ("grantee", "table_schema", "table_name"), ())
        if "table_name IN" in statement:
            return StatementResult(
                "s",
                "SUCCEEDED",
                ("table_name",),
                ((sql.DEPLOYMENT_STATE_TABLE,), (sql.MANAGED_GRANTS_TABLE,)),
            )
        if "deployment_state" in statement:
            return StatementResult(
                "d",
                "SUCCEEDED",
                (
                    "singleton",
                    "state_version",
                    "table_tag_key",
                    "workspace_column_tag_key",
                    "policy_scope",
                    "policy_name",
                    "last_successful_config_digest",
                    "pending_config_digest",
                    "lease_token",
                    "lease_acquired_at",
                ),
                (),
            )
        raise AssertionError(statement)

    with pytest.raises(ConfigError, match="required singleton"):
        discover_governance_state(FakeClient(handler), cfg)


def test_foreign_fixed_policy_blocks_but_owned_policy_is_replaceable() -> None:
    foreign = GovernanceState(catalog_policies=(CatalogPolicy("workspace_scope", "ROW_FILTER"),))
    with pytest.raises(ConfigError, match="without compatible deployment state"):
        build_plan(config(), sources(), foreign)
    owned = compatible_state()
    plan = build_plan(config(), sources(), owned)
    assert any(step.kind == "create_catalog_policy" for step in plan.steps)


def test_active_grants_matching_pending_digest_recover_after_final_state_failure() -> None:
    digest = "b" * 64
    transitional = GovernanceState(
        deployment=DeploymentState(
            2,
            "system_table_scope",
            "workspace_scope_column",
            "system",
            "workspace_scope",
            "a" * 64,
            digest,
        ),
        grants=(ManagedGrant("historical_group", "access", "audit", "ACTIVE", digest),),
        table_tags=(ManagedTableTag("access", "audit", "workspace_scoped"),),
        column_tags=(ManagedColumnTag("access", "audit", "workspace_id", ""),),
        catalog_policies=(CatalogPolicy("workspace_scope", "ROW_FILTER"),),
    )
    plan = build_plan(config(), sources(), transitional)
    assert any(step.kind == "revoke_prior_managed_select" for step in plan.steps)


def test_manifest_corruption_blocks_before_revoke() -> None:
    wrong_digest = compatible_state(
        ManagedGrant("historical_group", "access", "audit", "ACTIVE", "b" * 64)
    )
    assert wrong_digest.deployment is not None
    wrong_digest = GovernanceState(
        deployment=DeploymentState(
            2,
            "system_table_scope",
            "workspace_scope_column",
            "system",
            "workspace_scope",
            "a" * 64,
            None,
        ),
        grants=wrong_digest.grants,
        table_tags=wrong_digest.table_tags,
        column_tags=wrong_digest.column_tags,
        catalog_policies=wrong_digest.catalog_policies,
    )
    with pytest.raises(ConfigError, match="digest"):
        build_plan(config(), sources(), wrong_digest)

    untagged = GovernanceState(
        deployment=DeploymentState(
            2,
            "system_table_scope",
            "workspace_scope_column",
            "system",
            "workspace_scope",
            "a" * 64,
            None,
        ),
        grants=(ManagedGrant("historical_group", "access", "audit", "ACTIVE", "a" * 64),),
        catalog_policies=(CatalogPolicy("workspace_scope", "ROW_FILTER"),),
    )
    with pytest.raises(ConfigError, match="discovered tagged"):
        build_plan(config(), sources(), untagged)


def test_non_workspace_column_tag_blocks_and_stale_account_shared_is_explicit() -> None:
    rogue = GovernanceState(column_tags=(ManagedColumnTag("access", "audit", "account_id", ""),))
    with pytest.raises(ConfigError, match="non-workspace_id"):
        build_plan(config(), sources(), rogue)

    managed = compatible_state(ManagedGrant("bu_alpha", "access", "audit", "ACTIVE", "a" * 64))
    missing_column_tag = GovernanceState(
        deployment=managed.deployment,
        grants=managed.grants,
        table_tags=managed.table_tags,
        catalog_policies=managed.catalog_policies,
    )
    with pytest.raises(ConfigError, match="missing its column tag"):
        build_plan(config(), sources(), missing_column_tag)

    stale = GovernanceState(
        table_tags=(ManagedTableTag("billing", "list_prices", "account_shared"),)
    )
    plan = build_plan(config(), sources(), stale)
    assert plan.stale_account_shared_sources == ("system.billing.list_prices",)
    assert "external grants require audit" in plan.redacted()["staleAccountSharedAction"]
