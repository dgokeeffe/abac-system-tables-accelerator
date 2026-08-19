from __future__ import annotations

import pytest

from abac_system_tables import sql
from abac_system_tables.config import ConfigError, loads_config
from tests.helpers import valid_config_text


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


def test_governed_table_tag_declares_allowed_dispositions() -> None:
    statement = sql.create_governed_tag(
        "system_table_scope", ("workspace_scoped", "account_shared")
    )
    assert "VALUES ('workspace_scoped', 'account_shared')" in statement
    assert "VALUES ()" in sql.create_governed_tag("workspace_scope_column")


def test_udf_is_fail_closed_and_group_scoped() -> None:
    statement = sql.create_udf(loads_config(valid_config_text()))
    assert "workspace_id IS NOT NULL" in statement
    assert "is_account_group_member('bu_alpha')" in statement
    assert "workspace_id IN ('111', '222')" in statement
    assert "is_account_group_member('bu_beta')" in statement
    assert "workspace_id IN ('333')" in statement
    assert "ELSE TRUE" not in statement


def test_policy_matches_governed_table_and_column_tags() -> None:
    statement = sql.create_policy(loads_config(valid_config_text()))
    assert "CREATE OR REPLACE POLICY workspace_scope" in statement
    assert "TO `account users`" in statement
    assert "EXCEPT `facade_admins`, `facade_pipeline`" in statement
    assert "has_tag_value('system_table_scope', 'workspace_scoped')" in statement
    assert "has_tag('workspace_scope_column')" in statement
    assert "USING COLUMNS (workspace_scope)" in statement


def test_materialized_view_and_tags_target_facade() -> None:
    config = loads_config(valid_config_text())
    mv = sql.create_materialized_view(config, "access", "audit")
    assert "CREATE OR REPLACE MATERIALIZED VIEW `facade_catalog`.`published`.`access__audit`" in mv
    assert "SCHEDULE EVERY 24 HOURS" in mv
    assert "AS SELECT * FROM `system`.`access`.`audit`" in mv
    assert "ALTER COLUMN `workspace_id` SET TAGS" in sql.set_workspace_column_tag(
        config, "access", "audit"
    )


def test_grants_and_reconciliation_revokes_cannot_target_system() -> None:
    config = loads_config(valid_config_text())
    statements = sql.grants(config, ("access__audit", "billing__list_prices"))
    revokes = [
        sql.revoke_grant(config, "CATALOG", "facade_catalog", "old_group", "ALL_PRIVILEGES"),
        sql.revoke_grant(config, "SCHEMA", "published", "old_group", "APPLY_TAG"),
        sql.revoke_grant(config, "TABLE", "access__audit", "old_group", "SELECT"),
    ]
    assert len(statements) == 14
    assert all("`facade_catalog`" in statement for statement in statements + revokes)
    assert all("`system`" not in statement for statement in statements + revokes)
    assert all(statement.startswith("REVOKE") for statement in revokes)
    assert "REVOKE ALL PRIVILEGES ON CATALOG" in revokes[0]
    assert "REVOKE APPLY TAG ON SCHEMA" in revokes[1]
    consumer_statements = [statement for statement in statements if "`bu_" in statement]
    assert not any("SELECT ON SCHEMA" in statement for statement in consumer_statements)
    assert sum("GRANT SELECT ON TABLE" in statement for statement in consumer_statements) == 4
    assert not any("EXECUTE" in statement for statement in statements)


def test_discovery_is_complete_and_read_only() -> None:
    statement = sql.discovery_sql()
    assert "system.information_schema.tables" in statement
    assert "LEFT JOIN source_columns" in statement
    assert "table_schema <> 'information_schema'" in statement
    assert not any(word in statement.upper() for word in ("CREATE ", "ALTER ", "GRANT ", "DROP "))


def test_grant_discovery_covers_every_direct_catalog_schema_and_table_privilege() -> None:
    statement = sql.facade_grants_sql(loads_config(valid_config_text()))
    assert statement.count("inherited_from = 'NONE'") == 3
    assert "catalog_privileges" in statement
    assert "privilege_type IN" not in statement
