"""Deterministic, injection-resistant Databricks SQL generation."""

from __future__ import annotations

import re

from .config import Config, ConfigError

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_PRINCIPAL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 @._+:/-]{0,254}$")
POLICY_NAME = "workspace_scope"
POLICY_SCOPE = "system"
STATE_VERSION = 2
MANAGED_GRANTS_TABLE = "managed_grants"
DEPLOYMENT_STATE_TABLE = "deployment_state"
LOCK_TIMEOUT_MINUTES = 30


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


def governance_relation(config: Config, name: str) -> str:
    return relation(config.governance.catalog, config.governance.schema, name)


def system_relation(schema: str, table: str) -> str:
    return relation("system", schema, table)


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
    return f"DESCRIBE TABLE {system_relation(source_schema, source_table)}"


def direct_table_tags_sql(config: Config) -> str:
    return f"""SELECT schema_name, table_name, tag_value
FROM system.information_schema.table_tags
WHERE catalog_name = 'system' AND tag_name = {literal(config.tags.table_key)}
ORDER BY schema_name, table_name"""  # noqa: S608


def direct_column_tags_sql(config: Config) -> str:
    return f"""SELECT schema_name, table_name, column_name, tag_value
FROM system.information_schema.column_tags
WHERE catalog_name = 'system' AND tag_name = {literal(config.tags.workspace_column_key)}
ORDER BY schema_name, table_name, column_name"""  # noqa: S608


def governance_state_tables_sql(config: Config) -> str:
    return f"""SELECT table_name
FROM system.information_schema.tables
WHERE table_catalog = {literal(config.governance.catalog)}
  AND table_schema = {literal(config.governance.schema)}
  AND table_name IN ({literal(MANAGED_GRANTS_TABLE)}, {literal(DEPLOYMENT_STATE_TABLE)})
ORDER BY table_name"""  # noqa: S608


def deployment_state_sql(config: Config) -> str:
    return f"""SELECT singleton, state_version, table_tag_key, workspace_column_tag_key,
  policy_scope, policy_name, last_successful_config_digest, pending_config_digest,
  lease_token, CAST(lease_acquired_at AS STRING) AS lease_acquired_at
FROM {governance_relation(config, DEPLOYMENT_STATE_TABLE)}"""  # noqa: S608


def catalog_policies_sql() -> str:
    return "SHOW POLICIES ON CATALOG system"


def existing_consumer_selects_sql(config: Config) -> str:
    consumers = ", ".join(literal(group.name) for group in config.consumer_groups)
    return f"""SELECT grantee, table_schema, table_name
FROM system.information_schema.table_privileges
WHERE table_catalog = 'system'
  AND privilege_type = 'SELECT'
  AND inherited_from = 'NONE'
  AND grantee IN ({consumers})
ORDER BY grantee, table_schema, table_name"""  # noqa: S608


def managed_grants_sql(config: Config) -> str:
    return f"""SELECT principal, table_schema, table_name, status, config_digest
FROM {governance_relation(config, MANAGED_GRANTS_TABLE)}
ORDER BY principal, table_schema, table_name"""  # noqa: S608


def create_governance_catalog(config: Config) -> str:
    return f"CREATE CATALOG IF NOT EXISTS {identifier(config.governance.catalog)}"


def create_governance_schema(config: Config) -> str:
    return (
        "CREATE SCHEMA IF NOT EXISTS "
        f"{relation(config.governance.catalog, config.governance.schema)}"
    )


def create_managed_grants_table(config: Config) -> str:
    return f"""CREATE TABLE IF NOT EXISTS {governance_relation(config, MANAGED_GRANTS_TABLE)} (
  principal STRING NOT NULL,
  table_schema STRING NOT NULL,
  table_name STRING NOT NULL,
  status STRING NOT NULL,
  config_digest STRING NOT NULL,
  updated_at TIMESTAMP NOT NULL
)
COMMENT 'Accelerator-owned direct system-table SELECT grant manifest; contains no system rows'"""


def create_deployment_state_table(config: Config) -> str:
    return f"""CREATE TABLE IF NOT EXISTS {governance_relation(config, DEPLOYMENT_STATE_TABLE)} (
  singleton STRING NOT NULL,
  state_version INT NOT NULL,
  table_tag_key STRING NOT NULL,
  workspace_column_tag_key STRING NOT NULL,
  policy_scope STRING NOT NULL,
  policy_name STRING NOT NULL,
  last_successful_config_digest STRING,
  pending_config_digest STRING,
  lease_token STRING,
  lease_acquired_at TIMESTAMP,
  updated_at TIMESTAMP NOT NULL
)
COMMENT 'Immutable accelerator control-plane identity and last successful config digest'"""


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
    target = governance_relation(config, "workspace_allowed")
    clauses: list[str] = []
    for group in config.consumer_groups:
        ids = ", ".join(literal(item) for item in sorted(group.workspace_ids))
        clauses.append(
            f"(is_account_group_member({literal(group.name)}) AND workspace_id IN ({ids}))"
        )
    predicate = "\n    OR ".join(clauses)
    return f"""CREATE OR REPLACE FUNCTION {target}(workspace_id STRING)
RETURNS BOOLEAN
COMMENT 'Fail-closed direct system-table workspace entitlement predicate'
RETURN workspace_id IS NOT NULL AND (
    {predicate}
)"""


def set_table_tag(config: Config, source_schema: str, source_table: str, disposition: str) -> str:
    return (
        f"ALTER TABLE {system_relation(source_schema, source_table)} SET TAGS "
        f"({literal(config.tags.table_key)} = {literal(disposition)})"
    )


def set_workspace_column_tag(config: Config, source_schema: str, source_table: str) -> str:
    return (
        f"ALTER TABLE {system_relation(source_schema, source_table)} "
        f"ALTER COLUMN {identifier('workspace_id')} SET TAGS "
        f"({literal(config.tags.workspace_column_key)} = '')"
    )


def create_policy(config: Config) -> str:
    udf = governance_relation(config, "workspace_allowed")
    trusted = ", ".join(principal(item) for item in config.trusted_principals)
    return f"""CREATE OR REPLACE POLICY {POLICY_NAME}
ON CATALOG system
COMMENT 'Fail-closed direct system-table workspace policy managed by the accelerator'
ROW FILTER {udf}
TO `account users`
EXCEPT {trusted}
FOR TABLES
WHEN has_tag_value({literal(config.tags.table_key)}, 'workspace_scoped')
MATCH COLUMNS has_tag({literal(config.tags.workspace_column_key)}) AS workspace_scope
USING COLUMNS (workspace_scope)"""


def show_effective_policy(source_schema: str, source_table: str) -> str:
    return f"SHOW EFFECTIVE POLICIES ON TABLE {system_relation(source_schema, source_table)}"


def revoke_managed_select(source_schema: str, source_table: str, grantee: str) -> str:
    return (
        f"REVOKE SELECT ON TABLE {system_relation(source_schema, source_table)} "  # noqa: S608
        f"FROM {principal(grantee)}"
    )


def clear_managed_grants(config: Config) -> str:
    return f"DELETE FROM {governance_relation(config, MANAGED_GRANTS_TABLE)}"  # noqa: S608


def insert_pending_grants(config: Config, grants: tuple[tuple[str, str, str], ...]) -> str:
    if not grants:
        raise ConfigError("cannot create an empty managed grant manifest")
    rows = ",\n  ".join(
        "("
        + ", ".join(
            [
                literal(grantee),
                literal(schema),
                literal(table),
                "'PENDING'",
                literal(config.digest),
                "current_timestamp()",
            ]
        )
        + ")"
        for grantee, schema, table in grants
    )
    return f"""INSERT INTO {governance_relation(config, MANAGED_GRANTS_TABLE)}
  (principal, table_schema, table_name, status, config_digest, updated_at)
VALUES
  {rows}"""  # noqa: S608


def grant_navigation(config: Config, schemas: tuple[str, ...]) -> list[str]:
    statements: list[str] = []
    for group in config.consumer_groups:
        quoted = principal(group.name)
        statements.append(f"GRANT USE CATALOG ON CATALOG system TO {quoted}")
        statements.extend(
            f"GRANT USE SCHEMA ON SCHEMA {relation('system', schema)} TO {quoted}"
            for schema in schemas
        )
    return statements


def grant_select(source_schema: str, source_table: str, grantee: str) -> str:
    return (
        f"GRANT SELECT ON TABLE {system_relation(source_schema, source_table)} "
        f"TO {principal(grantee)}"
    )


def activate_managed_grants(config: Config) -> str:
    return f"""UPDATE {governance_relation(config, MANAGED_GRANTS_TABLE)}
SET status = 'ACTIVE', updated_at = current_timestamp()
WHERE config_digest = {literal(config.digest)} AND status = 'PENDING'"""  # noqa: S608


def initialize_deployment_state(config: Config) -> str:
    target = governance_relation(config, DEPLOYMENT_STATE_TABLE)
    return f"""MERGE INTO {target} AS target
USING (SELECT
  'system_tables_abac' AS singleton,
  {STATE_VERSION} AS state_version,
  {literal(config.tags.table_key)} AS table_tag_key,
  {literal(config.tags.workspace_column_key)} AS workspace_column_tag_key,
  {literal(POLICY_SCOPE)} AS policy_scope,
  {literal(POLICY_NAME)} AS policy_name,
  CAST(NULL AS STRING) AS last_successful_config_digest,
  CAST(NULL AS STRING) AS pending_config_digest,
  CAST(NULL AS STRING) AS lease_token,
  CAST(NULL AS TIMESTAMP) AS lease_acquired_at,
  current_timestamp() AS updated_at
) AS source
ON target.singleton = source.singleton
WHEN NOT MATCHED THEN INSERT *"""


def deployment_lock_plan_marker(config: Config) -> str:
    """Deterministic plan marker; apply substitutes a unique runtime lease token."""
    return f"ACQUIRE RUNTIME LEASE ON {governance_relation(config, DEPLOYMENT_STATE_TABLE)}"


def acquire_deployment_lock(
    governance_catalog: str,
    governance_schema: str,
    lease_token: str,
) -> str:
    target = relation(governance_catalog, governance_schema, DEPLOYMENT_STATE_TABLE)
    return f"""UPDATE {target}
SET lease_token = {literal(lease_token)},
    lease_acquired_at = current_timestamp(),
    updated_at = current_timestamp()
WHERE singleton = 'system_tables_abac'
  AND (
    lease_token IS NULL
    OR lease_acquired_at IS NULL
    OR lease_acquired_at < current_timestamp() - INTERVAL {LOCK_TIMEOUT_MINUTES} MINUTES
  )"""  # noqa: S608


def deployment_lock_status(
    governance_catalog: str,
    governance_schema: str,
) -> str:
    target = relation(governance_catalog, governance_schema, DEPLOYMENT_STATE_TABLE)
    return f"""SELECT lease_token
FROM {target}
WHERE singleton = 'system_tables_abac'"""  # noqa: S608


def renew_deployment_lock(
    governance_catalog: str,
    governance_schema: str,
    lease_token: str,
) -> str:
    target = relation(governance_catalog, governance_schema, DEPLOYMENT_STATE_TABLE)
    return f"""UPDATE {target}
SET lease_acquired_at = current_timestamp(), updated_at = current_timestamp()
WHERE singleton = 'system_tables_abac' AND lease_token = {literal(lease_token)}"""  # noqa: S608


def release_deployment_lock(
    governance_catalog: str,
    governance_schema: str,
    lease_token: str,
) -> str:
    target = relation(governance_catalog, governance_schema, DEPLOYMENT_STATE_TABLE)
    return f"""UPDATE {target}
SET lease_token = NULL, lease_acquired_at = NULL, updated_at = current_timestamp()
WHERE singleton = 'system_tables_abac' AND lease_token = {literal(lease_token)}"""  # noqa: S608


def set_pending_deployment_state(config: Config) -> str:
    target = governance_relation(config, DEPLOYMENT_STATE_TABLE)
    return f"""UPDATE {target}
SET pending_config_digest = {literal(config.digest)}, updated_at = current_timestamp()
WHERE singleton = 'system_tables_abac'"""  # noqa: S608


def upsert_deployment_state(config: Config) -> str:
    target = governance_relation(config, DEPLOYMENT_STATE_TABLE)
    return f"""MERGE INTO {target} AS target
USING (SELECT
  'system_tables_abac' AS singleton,
  {STATE_VERSION} AS state_version,
  {literal(config.tags.table_key)} AS table_tag_key,
  {literal(config.tags.workspace_column_key)} AS workspace_column_tag_key,
  {literal(POLICY_SCOPE)} AS policy_scope,
  {literal(POLICY_NAME)} AS policy_name,
  {literal(config.digest)} AS last_successful_config_digest,
  CAST(NULL AS STRING) AS pending_config_digest,
  CAST(NULL AS STRING) AS lease_token,
  CAST(NULL AS TIMESTAMP) AS lease_acquired_at,
  current_timestamp() AS updated_at
) AS source
ON target.singleton = source.singleton
WHEN MATCHED THEN UPDATE SET
  last_successful_config_digest = source.last_successful_config_digest,
  pending_config_digest = source.pending_config_digest,
  updated_at = source.updated_at
WHEN NOT MATCHED THEN INSERT *"""


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
    if catalog != "system":
        raise ConfigError("verification relation must be in the system catalog")
    allowed = ", ".join(literal(item) for item in sorted(allowed_workspace_ids))
    target = relation(catalog, schema, table)
    return f"""SELECT
  COUNT(DISTINCT workspace_id) AS observed_count,
  COUNT_IF(workspace_id IS NULL OR workspace_id NOT IN ({allowed})) AS violation_count
FROM {target}"""  # noqa: S608


def verify_access_sql(relation_name: str) -> str:
    catalog, schema, table = relation_name.split(".")
    if catalog != "system":
        raise ConfigError("verification relation must be in the system catalog")
    return f"SELECT * FROM {relation(catalog, schema, table)} LIMIT 0"  # noqa: S608
