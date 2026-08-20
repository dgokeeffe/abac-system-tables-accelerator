from __future__ import annotations

import pytest

from abac_system_tables import sql
from abac_system_tables.config import ConfigError, loads_config
from tests.helpers import valid_config_text


def config():
    return loads_config(valid_config_text())


def test_sql_quoting_rejects_injection_and_escapes_literals() -> None:
    assert sql.literal("O'Reilly") == "'O''Reilly'"
    assert sql.identifier("safe_name") == "`safe_name`"
    assert sql.principal("BU readers") == "`BU readers`"
    with pytest.raises(ConfigError):
        sql.identifier("x; DROP TABLE y")
    with pytest.raises(ConfigError):
        sql.principal("group`; DROP")
    with pytest.raises(ConfigError):
        sql.literal("line\nbreak")


def test_direct_tags_target_original_system_table() -> None:
    table = sql.set_table_tag(config(), "access", "audit", "workspace_scoped")
    column = sql.set_workspace_column_tag(config(), "access", "audit")
    assert table.startswith("ALTER TABLE `system`.`access`.`audit` SET TAGS")
    assert "ALTER COLUMN `workspace_id` SET TAGS" in column
    assert "MATERIALIZED VIEW" not in table + column


def test_policy_is_catalog_scoped_and_fail_closed() -> None:
    statement = sql.create_policy(config())
    assert "CREATE OR REPLACE POLICY workspace_scope" in statement
    assert "ON CATALOG system" in statement
    assert "TO `account users`" in statement
    assert "EXCEPT `governance_admins`, `governance_pipeline`" in statement
    assert "has_tag_value('system_table_scope', 'workspace_scoped')" in statement
    assert "has_tag('workspace_scope_column')" in statement
    assert "USING COLUMNS (workspace_scope)" in statement


def test_udf_is_group_scoped_and_deny_by_default() -> None:
    statement = sql.create_udf(config())
    assert "`governance_catalog`.`system_tables_abac`.`workspace_allowed`" in statement
    assert "workspace_id IS NOT NULL" in statement
    assert "is_account_group_member('bu_alpha')" in statement
    assert "workspace_id IN ('111', '222')" in statement
    assert "ELSE TRUE" not in statement


def test_direct_navigation_select_and_revoke_sql() -> None:
    navigation = sql.grant_navigation(config(), ("access", "billing"))
    assert "GRANT USE CATALOG ON CATALOG system TO `bu_alpha`" in navigation
    assert "GRANT USE SCHEMA ON SCHEMA `system`.`access` TO `bu_beta`" in navigation
    grant = sql.grant_select("access", "audit", "bu_alpha")
    revoke = sql.revoke_managed_select("access", "audit", "old_group")
    assert grant == "GRANT SELECT ON TABLE `system`.`access`.`audit` TO `bu_alpha`"
    assert revoke == "REVOKE SELECT ON TABLE `system`.`access`.`audit` FROM `old_group`"


def test_managed_state_sql_contains_no_system_rows() -> None:
    grants = sql.create_managed_grants_table(config())
    deployment = sql.create_deployment_state_table(config())
    assert "principal STRING" in grants and "table_schema STRING" in grants
    assert "state_version INT" in deployment and "policy_scope STRING" in deployment
    assert "lease_token STRING" in deployment and "lease_acquired_at TIMESTAMP" in deployment
    assert "SELECT * FROM system" not in grants + deployment
    pending = sql.insert_pending_grants(config(), (("bu_alpha", "access", "audit"),))
    assert "'PENDING'" in pending and config().digest in pending
    assert "UPDATE" in sql.activate_managed_grants(config())
    assert "WHEN NOT MATCHED THEN INSERT" in sql.initialize_deployment_state(config())
    assert "MERGE INTO" in sql.upsert_deployment_state(config())


def test_deployment_lease_sql_is_conditional_bounded_and_owner_scoped() -> None:
    token = "a" * 32
    acquire = sql.acquire_deployment_lock("governance_catalog", "system_tables_abac", token)
    renew = sql.renew_deployment_lock("governance_catalog", "system_tables_abac", token)
    release = sql.release_deployment_lock("governance_catalog", "system_tables_abac", token)
    assert "lease_token IS NULL" in acquire
    assert f"INTERVAL {sql.LOCK_TIMEOUT_MINUTES} MINUTES" in acquire
    assert token in acquire and token in renew and token in release
    assert "WHERE singleton = 'system_tables_abac' AND lease_token" in renew
    assert "SET lease_token = NULL" in release
    assert sql.deployment_lock_plan_marker(config()).startswith("ACQUIRE RUNTIME LEASE")


def test_discovery_and_state_queries_are_read_only() -> None:
    statements = [
        sql.discovery_sql(),
        sql.governance_state_tables_sql(config()),
        sql.direct_table_tags_sql(config()),
        sql.direct_column_tags_sql(config()),
        sql.existing_consumer_selects_sql(config()),
    ]
    assert "LEFT JOIN source_columns" in statements[0]
    assert all(
        not any(word in statement.upper() for word in ("CREATE ", "ALTER ", "GRANT ", "DROP "))
        for statement in statements
    )


def test_no_generated_materialized_view_or_schedule_symbols() -> None:
    generated = "\n".join(
        [
            sql.create_udf(config()),
            sql.create_policy(config()),
            sql.set_table_tag(config(), "access", "audit", "workspace_scoped"),
            sql.grant_select("access", "audit", "bu_alpha"),
        ]
    ).upper()
    assert "MATERIALIZED VIEW" not in generated
    assert "SCHEDULE EVERY" not in generated
