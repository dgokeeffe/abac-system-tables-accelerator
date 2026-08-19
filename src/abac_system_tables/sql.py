"""Deterministic, injection-resistant Databricks SQL generation."""

from __future__ import annotations

import re

from .config import Config, ConfigError

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_PRINCIPAL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 @._+:/-]{0,254}$")


def identifier(value: str) -> str:
    if not _IDENTIFIER.fullmatch(value):
        raise ConfigError(f"unsafe SQL identifier: {value!r}")
    return f"`{value}`"


def principal(value: str) -> str:
    if not _PRINCIPAL.fullmatch(value) or "`" in value or ";" in value:
        raise ConfigError(f"unsafe SQL principal: {value!r}")
    return f"`{value}`"


def literal(value: str) -> str:
    if any(ord(char) < 32 for char in value):
        raise ConfigError("SQL literals must not contain control characters")
    return "'" + value.replace("'", "''") + "'"


def relation(*parts: str) -> str:
    return ".".join(identifier(part) for part in parts)


def facade_name(schema: str, table: str) -> str:
    value = f"{schema}__{table}"
    if len(value) > 128 or not _IDENTIFIER.fullmatch(value):
        raise ConfigError(f"source name cannot be mapped safely: {schema}.{table}")
    return value


def discovery_sql() -> str:
    return """WITH source_tables AS (
  SELECT table_schema, table_name, table_type
  FROM system.information_schema.tables
  WHERE table_catalog = 'system' AND table_schema <> 'information_schema'
), source_columns AS (
  SELECT table_schema, table_name, column_name, data_type
  FROM system.information_schema.columns
  WHERE table_catalog = 'system' AND table_schema <> 'information_schema'
)
SELECT t.table_schema, t.table_name, t.table_type,
  COUNT(c.column_name) AS column_count,
  MAX(CASE WHEN lower(c.column_name) = 'workspace_id' THEN upper(c.data_type) END)
    AS workspace_id_type
FROM source_tables t LEFT JOIN source_columns c
  ON t.table_schema = c.table_schema AND t.table_name = c.table_name
GROUP BY t.table_schema, t.table_name, t.table_type
ORDER BY t.table_schema, t.table_name"""


def describe_source_sql(source_schema: str, source_table: str) -> str:
    """Read source columns when system.information_schema omits shared-table metadata."""
    return f"DESCRIBE TABLE {relation('system', source_schema, source_table)}"


def facade_objects_sql(config: Config) -> str:
    return f"""SELECT table_name, table_type
FROM system.information_schema.tables
WHERE table_catalog = {literal(config.facade.catalog)}
  AND table_schema = {literal(config.facade.schema)}
ORDER BY table_name"""  # noqa: S608


def facade_tags_sql(config: Config) -> str:
    return f"""SELECT table_name, tag_value
FROM system.information_schema.table_tags
WHERE catalog_name = {literal(config.facade.catalog)}
  AND schema_name = {literal(config.facade.schema)}
  AND tag_name = {literal(config.tags.table_key)}
ORDER BY table_name"""  # noqa: S608


def facade_grants_sql(config: Config) -> str:
    """Discover every direct privilege on the dedicated facade hierarchy."""
    return f"""SELECT object_type, object_name, grantee, privilege_type FROM (
  SELECT 'CATALOG' AS object_type, catalog_name AS object_name, grantee, privilege_type
  FROM system.information_schema.catalog_privileges
  WHERE catalog_name = {literal(config.facade.catalog)}
    AND inherited_from = 'NONE'
  UNION ALL
  SELECT 'SCHEMA' AS object_type, schema_name AS object_name, grantee, privilege_type
  FROM system.information_schema.schema_privileges
  WHERE catalog_name = {literal(config.facade.catalog)}
    AND schema_name = {literal(config.facade.schema)}
    AND inherited_from = 'NONE'
  UNION ALL
  SELECT 'TABLE' AS object_type, table_name AS object_name, grantee, privilege_type
  FROM system.information_schema.table_privileges
  WHERE table_catalog = {literal(config.facade.catalog)}
    AND table_schema = {literal(config.facade.schema)}
    AND inherited_from = 'NONE'
) ORDER BY object_type, object_name, grantee, privilege_type"""  # noqa: S608


def create_catalog(config: Config) -> str:
    return f"CREATE CATALOG IF NOT EXISTS {identifier(config.facade.catalog)}"


def create_schema(config: Config) -> str:
    return f"CREATE SCHEMA IF NOT EXISTS {relation(config.facade.catalog, config.facade.schema)}"


def create_governed_tag(tag_key: str, allowed_values: tuple[str, ...] = ()) -> str:
    values = " VALUES (" + ", ".join(literal(value) for value in allowed_values) + ")"
    return (
        f"CREATE GOVERNED TAG {identifier(tag_key)} "
        "DESCRIPTION 'Managed by the ABAC system tables accelerator'" + values
    )


def show_governed_tags() -> str:
    return "SHOW GOVERNED TAGS"


def describe_governed_tag(tag_key: str) -> str:
    return f"DESCRIBE GOVERNED TAG {identifier(tag_key)}"


def create_udf(config: Config) -> str:
    target = relation(config.facade.catalog, config.facade.schema, "workspace_allowed")
    clauses: list[str] = []
    for group in config.consumer_groups:
        ids = ", ".join(literal(item) for item in sorted(group.workspace_ids))
        clauses.append(
            f"(is_account_group_member({literal(group.name)}) AND workspace_id IN ({ids}))"
        )
    predicate = "\n    OR ".join(clauses)
    return f"""CREATE OR REPLACE FUNCTION {target}(workspace_id STRING)
RETURNS BOOLEAN
COMMENT 'Fail-closed workspace entitlement predicate managed by the accelerator'
RETURN workspace_id IS NOT NULL AND (
    {predicate}
)"""


def create_materialized_view(config: Config, source_schema: str, source_table: str) -> str:
    target = relation(
        config.facade.catalog, config.facade.schema, facade_name(source_schema, source_table)
    )
    source = relation("system", source_schema, source_table)
    return f"""CREATE OR REPLACE MATERIALIZED VIEW {target}
SCHEDULE EVERY {config.facade.refresh_every_hours} HOURS
COMMENT 'System table facade managed by the ABAC accelerator'
AS SELECT * FROM {source}"""  # noqa: S608


def drop_materialized_view(config: Config, name: str) -> str:
    target = relation(config.facade.catalog, config.facade.schema, name)
    return f"DROP MATERIALIZED VIEW IF EXISTS {target}"


def set_table_tag(config: Config, source_schema: str, source_table: str, disposition: str) -> str:
    target = relation(
        config.facade.catalog, config.facade.schema, facade_name(source_schema, source_table)
    )
    return (
        f"ALTER MATERIALIZED VIEW {target} SET TAGS "
        f"({literal(config.tags.table_key)} = {literal(disposition)})"
    )


def set_workspace_column_tag(config: Config, source_schema: str, source_table: str) -> str:
    target = relation(
        config.facade.catalog, config.facade.schema, facade_name(source_schema, source_table)
    )
    return (
        f"ALTER MATERIALIZED VIEW {target} ALTER COLUMN {identifier('workspace_id')} SET TAGS "
        f"({literal(config.tags.workspace_column_key)} = '')"
    )


def create_policy(config: Config) -> str:
    target = relation(config.facade.catalog, config.facade.schema)
    udf = relation(config.facade.catalog, config.facade.schema, "workspace_allowed")
    trusted = ", ".join(principal(item) for item in config.trusted_principals)
    return f"""CREATE OR REPLACE POLICY workspace_scope
ON SCHEMA {target}
COMMENT 'Workspace least-privilege policy managed by the accelerator'
ROW FILTER {udf}
TO `account users`
EXCEPT {trusted}
FOR TABLES
WHEN has_tag_value({literal(config.tags.table_key)}, 'workspace_scoped')
MATCH COLUMNS has_tag({literal(config.tags.workspace_column_key)}) AS workspace_scope
USING COLUMNS (workspace_scope)"""


def show_effective_policy(config: Config, name: str) -> str:
    target = relation(config.facade.catalog, config.facade.schema, name)
    return f"SHOW EFFECTIVE POLICIES ON TABLE {target}"


def revoke_grant(
    config: Config,
    object_type: str,
    object_name: str,
    grantee: str,
    privilege: str,
) -> str:
    if not re.fullmatch(r"[A-Z][A-Z_]*", privilege):
        raise ConfigError(f"unsupported privilege metadata: {privilege}")
    sql_privilege = privilege.replace("_", " ")
    if object_type == "CATALOG":
        target = identifier(config.facade.catalog)
    elif object_type == "SCHEMA":
        target = relation(config.facade.catalog, config.facade.schema)
    elif object_type == "TABLE":
        target = relation(config.facade.catalog, config.facade.schema, object_name)
    else:
        raise ConfigError(f"unsupported grant object type: {object_type}")
    return f"REVOKE {sql_privilege} ON {object_type} {target} FROM {principal(grantee)}"


def grants(config: Config, published_names: tuple[str, ...]) -> list[str]:
    """Grant consumers only named policy-gated MVs; trusted principals can inspect the schema."""
    catalog = identifier(config.facade.catalog)
    schema = relation(config.facade.catalog, config.facade.schema)
    statements: list[str] = []
    for group in config.consumer_groups:
        quoted = principal(group.name)
        statements.extend(
            [
                f"GRANT USE CATALOG ON CATALOG {catalog} TO {quoted}",
                f"GRANT USE SCHEMA ON SCHEMA {schema} TO {quoted}",
            ]
        )
        statements.extend(
            "GRANT SELECT ON TABLE "
            f"{relation(config.facade.catalog, config.facade.schema, name)} TO {quoted}"
            for name in published_names
        )
    for name in config.trusted_principals:
        quoted = principal(name)
        statements.extend(
            [
                f"GRANT USE CATALOG ON CATALOG {catalog} TO {quoted}",
                f"GRANT USE SCHEMA ON SCHEMA {schema} TO {quoted}",
                f"GRANT SELECT ON SCHEMA {schema} TO {quoted}",
            ]
        )
    return statements


def identity_sql() -> str:
    return "SELECT current_user() AS current_identity, session_user() AS session_identity"


def verify_membership_sql(consumer_group: str, trusted: tuple[str, ...]) -> str:
    expressions = [f"is_account_group_member({literal(consumer_group)}) AS consumer_member"]
    expressions.extend(
        f"is_account_group_member({literal(name)}) AS trusted_member_{index}"
        for index, name in enumerate(trusted)
    )
    return "SELECT " + ", ".join(expressions)


def verify_scoped_sql(relation_name: str, allowed_workspace_ids: tuple[str, ...]) -> str:
    catalog, schema, table = relation_name.split(".")
    allowed = ", ".join(literal(item) for item in sorted(allowed_workspace_ids))
    target = relation(catalog, schema, table)
    return f"""SELECT
  COUNT(DISTINCT workspace_id) AS observed_count,
  COUNT_IF(workspace_id IS NULL OR workspace_id NOT IN ({allowed})) AS violation_count
FROM {target}"""  # noqa: S608


def verify_access_sql(relation_name: str) -> str:
    catalog, schema, table = relation_name.split(".")
    return f"SELECT * FROM {relation(catalog, schema, table)} LIMIT 0"  # noqa: S608
