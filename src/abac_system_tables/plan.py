"""Direct system-table discovery, persisted-state loading, and deterministic planning."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from . import sql
from .client import SqlClient, StatementError
from .config import Config, ConfigError

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_PRINCIPAL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 @._+:/-]{0,254}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_LEASE_TOKEN = re.compile(r"^[0-9a-f]{32}$")
_MANAGED_VALUES = frozenset({"workspace_scoped", "account_shared"})


@dataclass(frozen=True, slots=True)
class SourceTable:
    schema: str
    table: str
    table_type: str
    column_count: int
    workspace_id_type: str | None

    @property
    def full_name(self) -> str:
        return f"system.{self.schema}.{self.table}"


@dataclass(frozen=True, slots=True)
class DeploymentState:
    state_version: int
    table_tag_key: str
    workspace_column_tag_key: str
    policy_scope: str
    policy_name: str
    last_successful_config_digest: str | None
    pending_config_digest: str | None
    lease_token: str | None = None
    lease_acquired_at: str | None = None


@dataclass(frozen=True, slots=True)
class CatalogPolicy:
    name: str
    policy_type: str


@dataclass(frozen=True, slots=True)
class ManagedGrant:
    principal: str
    schema: str
    table: str
    status: str
    config_digest: str


@dataclass(frozen=True, slots=True)
class ExternalSelect:
    principal: str
    schema: str
    table: str


@dataclass(frozen=True, slots=True)
class ManagedTableTag:
    schema: str
    table: str
    value: str

    @property
    def full_name(self) -> str:
        return f"system.{self.schema}.{self.table}"


@dataclass(frozen=True, slots=True)
class ManagedColumnTag:
    schema: str
    table: str
    column: str
    value: str


@dataclass(frozen=True, slots=True)
class GovernanceState:
    deployment: DeploymentState | None = None
    grants: tuple[ManagedGrant, ...] = ()
    external_selects: tuple[ExternalSelect, ...] = ()
    table_tags: tuple[ManagedTableTag, ...] = ()
    column_tags: tuple[ManagedColumnTag, ...] = ()
    catalog_policies: tuple[CatalogPolicy, ...] = ()


@dataclass(frozen=True, slots=True)
class Disposition:
    source: SourceTable
    disposition: str
    reason: str


@dataclass(frozen=True, slots=True)
class PlanStep:
    order: int
    kind: str
    target: str
    statement: str
    tag_key: str | None = None
    tag_values: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Plan:
    config_digest: str
    governance_catalog: str
    governance_schema: str
    dispositions: tuple[Disposition, ...]
    governance_state: GovernanceState
    stale_workspace_scoped_sources: tuple[str, ...]
    stale_account_shared_sources: tuple[str, ...]
    steps: tuple[PlanStep, ...]

    @property
    def digest(self) -> str:
        deployment = self.governance_state.deployment
        payload = {
            "config_digest": self.config_digest,
            "governance": [self.governance_catalog, self.governance_schema],
            "sources": [
                {
                    "name": item.source.full_name,
                    "type": item.source.table_type,
                    "columns": item.source.column_count,
                    "workspace_type": item.source.workspace_id_type,
                    "disposition": item.disposition,
                }
                for item in self.dispositions
            ],
            "deployment_state": None
            if deployment is None
            else [
                deployment.state_version,
                deployment.table_tag_key,
                deployment.workspace_column_tag_key,
                deployment.policy_scope,
                deployment.policy_name,
                deployment.last_successful_config_digest,
                deployment.pending_config_digest,
                deployment.lease_token,
                deployment.lease_acquired_at,
            ],
            "managed_grants": [
                [item.principal, item.schema, item.table, item.status, item.config_digest]
                for item in self.governance_state.grants
            ],
            "external_selects": [
                [item.principal, item.schema, item.table]
                for item in self.governance_state.external_selects
            ],
            "table_tags": [
                [item.schema, item.table, item.value] for item in self.governance_state.table_tags
            ],
            "column_tags": [
                [item.schema, item.table, item.column, item.value]
                for item in self.governance_state.column_tags
            ],
            "catalog_policies": [
                [item.name, item.policy_type] for item in self.governance_state.catalog_policies
            ],
            "steps": [
                {"kind": step.kind, "statement": step.statement, "target": step.target}
                for step in self.steps
            ],
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    def redacted(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        sources: list[dict[str, str]] = []
        for item in self.dispositions:
            counts[item.disposition] = counts.get(item.disposition, 0) + 1
            sources.append(
                {
                    "source": item.source.full_name,
                    "disposition": item.disposition,
                    "reason": item.reason,
                }
            )
        return {
            "configDigest": self.config_digest,
            "planDigest": self.digest,
            "dispositionCounts": dict(sorted(counts.items())),
            "sources": sources,
            "deploymentStatePresent": self.governance_state.deployment is not None,
            "priorManagedGrantCount": len(self.governance_state.grants),
            "preservedExternalSelectCount": len(
                {
                    (item.principal, item.schema, item.table)
                    for item in self.governance_state.external_selects
                }
                - {
                    (item.principal, item.schema, item.table)
                    for item in self.governance_state.grants
                }
            ),
            "otherCatalogRowFilterPolicyCount": sum(
                item.policy_type == "ROW_FILTER" and item.name != sql.POLICY_NAME
                for item in self.governance_state.catalog_policies
            ),
            "staleWorkspaceScopedSources": list(self.stale_workspace_scoped_sources),
            "staleWorkspaceScopedAction": "tag retained; row policy remains fail-closed",
            "staleAccountSharedSources": list(self.stale_account_shared_sources),
            "staleAccountSharedAction": (
                "tag retained without row filtering; managed grants close, "
                "external grants require audit"
            ),
            "steps": [
                {
                    "order": step.order,
                    "kind": step.kind,
                    "targetRef": "sha256:" + hashlib.sha256(step.target.encode()).hexdigest()[:12],
                }
                for step in self.steps
            ],
        }


def _integer(value: str | None, label: str) -> int:
    try:
        result = int(value or "0")
    except ValueError as exc:
        raise ConfigError(f"discovery returned invalid integer for {label}") from exc
    if result < 0:
        raise ConfigError(f"discovery returned negative integer for {label}")
    return result


def parse_discovery(
    columns: tuple[str, ...], rows: tuple[tuple[str | None, ...], ...]
) -> tuple[SourceTable, ...]:
    required = ("table_schema", "table_name", "table_type", "column_count", "workspace_id_type")
    if columns != required:
        raise ConfigError(f"unexpected discovery schema: {columns!r}")
    tables: list[SourceTable] = []
    for row in rows:
        if len(row) != len(required):
            raise ConfigError("discovery returned a malformed row")
        schema, table, table_type, count, workspace_type = row
        if schema is None or table is None or table_type is None:
            raise ConfigError("discovery returned null table metadata")
        if not _IDENTIFIER.fullmatch(schema) or not _IDENTIFIER.fullmatch(table):
            raise ConfigError(f"unsafe source identifier returned by discovery: {schema}.{table}")
        tables.append(
            SourceTable(
                schema,
                table,
                table_type,
                _integer(count, f"{schema}.{table}"),
                workspace_type.upper() if workspace_type else None,
            )
        )
    names = [item.full_name for item in tables]
    if len(names) != len(set(names)):
        raise ConfigError("discovery returned duplicate system tables")
    return tuple(sorted(tables, key=lambda item: (item.schema, item.table)))


def _describe_source(client: SqlClient, source: SourceTable) -> SourceTable:
    try:
        result = client.execute(
            sql.describe_source_sql(source.schema, source.table), include_rows=True
        )
    except StatementError:
        return source
    if result.columns != ("col_name", "data_type", "comment"):
        raise ConfigError(f"unexpected DESCRIBE schema for {source.full_name}")
    column_count = 0
    workspace_type: str | None = None
    for row in result.rows:
        if len(row) != 3:
            raise ConfigError(f"malformed DESCRIBE row for {source.full_name}")
        name, data_type, _comment = row
        if not name or name.startswith("#") or not data_type:
            continue
        if not _IDENTIFIER.fullmatch(name):
            raise ConfigError(f"unsafe column name returned for {source.full_name}")
        column_count += 1
        if name.casefold() == "workspace_id":
            workspace_type = data_type.upper()
    return SourceTable(source.schema, source.table, source.table_type, column_count, workspace_type)


def discover(client: SqlClient) -> tuple[SourceTable, ...]:
    result = client.execute(sql.discovery_sql(), include_rows=True)
    sources = parse_discovery(result.columns, result.rows)
    return tuple(
        _describe_source(client, source) if source.column_count == 0 else source
        for source in sources
    )


def _rows(
    client: SqlClient, statement: str, expected: tuple[str, ...]
) -> tuple[tuple[str | None, ...], ...]:
    result = client.execute(statement, include_rows=True)
    if result.columns != expected:
        raise ConfigError(f"unexpected persisted-state schema: {result.columns!r}")
    if any(len(row) != len(expected) for row in result.rows):
        raise ConfigError("persisted-state discovery returned a malformed row")
    return result.rows


def _parse_deployment(rows: tuple[tuple[str | None, ...], ...]) -> DeploymentState | None:
    if not rows:
        return None
    if len(rows) != 1 or len(rows[0]) != 10 or any(value is None for value in rows[0][:6]):
        raise ConfigError("deployment_state must contain one complete singleton row")
    (
        singleton,
        version,
        table_key,
        column_key,
        scope,
        name,
        digest,
        pending_digest,
        lease_token,
        lease_acquired_at,
    ) = rows[0]
    if singleton != "system_tables_abac":
        raise ConfigError("deployment_state contains an unexpected singleton")
    assert version is not None and table_key is not None and column_key is not None
    assert scope is not None and name is not None
    if not _IDENTIFIER.fullmatch(table_key) or not _IDENTIFIER.fullmatch(column_key):
        raise ConfigError("deployment_state contains unsafe tag keys")
    if digest is not None and not _DIGEST.fullmatch(digest):
        raise ConfigError("deployment_state contains an invalid successful config digest")
    if pending_digest is not None and not _DIGEST.fullmatch(pending_digest):
        raise ConfigError("deployment_state contains an invalid pending config digest")
    if (lease_token is None) != (lease_acquired_at is None):
        raise ConfigError("deployment_state contains an incomplete lease")
    if lease_token is not None and not _LEASE_TOKEN.fullmatch(lease_token):
        raise ConfigError("deployment_state contains an invalid lease token")
    if lease_acquired_at is not None and (
        not lease_acquired_at.strip() or any(ord(char) < 32 for char in lease_acquired_at)
    ):
        raise ConfigError("deployment_state contains an invalid lease timestamp")
    return DeploymentState(
        _integer(version, "state_version"),
        table_key,
        column_key,
        scope,
        name,
        digest,
        pending_digest,
        lease_token,
        lease_acquired_at,
    )


def _parse_grants(rows: tuple[tuple[str | None, ...], ...]) -> tuple[ManagedGrant, ...]:
    grants: list[ManagedGrant] = []
    for row in rows:
        if len(row) != 5 or any(value is None for value in row):
            raise ConfigError("managed_grants contains a null or malformed row")
        grantee, schema, table, status, digest = row
        assert grantee is not None and schema is not None and table is not None
        assert status is not None and digest is not None
        if not _PRINCIPAL.fullmatch(grantee) or "`" in grantee or ";" in grantee:
            raise ConfigError("managed_grants contains an unsafe principal")
        if not _IDENTIFIER.fullmatch(schema) or not _IDENTIFIER.fullmatch(table):
            raise ConfigError("managed_grants contains an unsafe system-table identifier")
        if status not in {"PENDING", "ACTIVE"} or not _DIGEST.fullmatch(digest):
            raise ConfigError("managed_grants contains invalid status or digest")
        grants.append(ManagedGrant(grantee, schema, table, status, digest))
    keys = [(item.principal, item.schema, item.table) for item in grants]
    if len(keys) != len(set(keys)):
        raise ConfigError("managed_grants contains duplicate grant tuples")
    return tuple(sorted(grants, key=lambda item: (item.principal, item.schema, item.table)))


def _parse_external_selects(rows: tuple[tuple[str | None, ...], ...]) -> tuple[ExternalSelect, ...]:
    grants: list[ExternalSelect] = []
    for row in rows:
        if len(row) != 3 or any(value is None for value in row):
            raise ConfigError("external SELECT discovery contains a null or malformed row")
        grantee, schema, table = row
        assert grantee is not None and schema is not None and table is not None
        if not _PRINCIPAL.fullmatch(grantee) or "`" in grantee or ";" in grantee:
            raise ConfigError("external SELECT discovery contains an unsafe principal")
        if not _IDENTIFIER.fullmatch(schema) or not _IDENTIFIER.fullmatch(table):
            raise ConfigError("external SELECT discovery contains unsafe identifiers")
        grants.append(ExternalSelect(grantee, schema, table))
    keys = [(item.principal, item.schema, item.table) for item in grants]
    if len(keys) != len(set(keys)):
        raise ConfigError("external SELECT discovery contains duplicate tuples")
    return tuple(sorted(grants, key=lambda item: (item.principal, item.schema, item.table)))


def _parse_table_tags(rows: tuple[tuple[str | None, ...], ...]) -> tuple[ManagedTableTag, ...]:
    tags: list[ManagedTableTag] = []
    for schema, table, value in rows:
        if schema is None or table is None or value is None:
            raise ConfigError("direct table tag discovery returned null metadata")
        if not _IDENTIFIER.fullmatch(schema) or not _IDENTIFIER.fullmatch(table):
            raise ConfigError("direct table tag discovery returned unsafe identifiers")
        tags.append(ManagedTableTag(schema, table, value))
    return tuple(sorted(tags, key=lambda item: (item.schema, item.table)))


def _parse_column_tags(rows: tuple[tuple[str | None, ...], ...]) -> tuple[ManagedColumnTag, ...]:
    tags: list[ManagedColumnTag] = []
    for schema, table, column, value in rows:
        if schema is None or table is None or column is None or value is None:
            raise ConfigError("direct column tag discovery returned null metadata")
        if any(not _IDENTIFIER.fullmatch(part) for part in (schema, table, column)):
            raise ConfigError("direct column tag discovery returned unsafe identifiers")
        tags.append(ManagedColumnTag(schema, table, column, value))
    return tuple(sorted(tags, key=lambda item: (item.schema, item.table, item.column)))


def _discover_catalog_policies(client: SqlClient) -> tuple[CatalogPolicy, ...]:
    result = client.execute(sql.catalog_policies_sql(), include_rows=True)
    normalized = {
        name.casefold().replace("_", "").replace(" ", ""): index
        for index, name in enumerate(result.columns)
    }
    if "policyname" not in normalized or "policytype" not in normalized:
        raise ConfigError("catalog policy discovery returned an unexpected schema")
    name_index = normalized["policyname"]
    type_index = normalized["policytype"]
    policies: list[CatalogPolicy] = []
    for row in result.rows:
        if len(row) != len(result.columns):
            raise ConfigError("catalog policy discovery returned a malformed row")
        name, policy_type = row[name_index], row[type_index]
        if name is None or policy_type is None or not _IDENTIFIER.fullmatch(name):
            raise ConfigError("catalog policy discovery returned unsafe metadata")
        policies.append(CatalogPolicy(name, policy_type.replace(" ", "_").upper()))
    names = [item.name for item in policies]
    if len(names) != len(set(names)):
        raise ConfigError("catalog policy discovery returned duplicate policy names")
    return tuple(sorted(policies, key=lambda item: item.name))


def discover_governance_state(client: SqlClient, config: Config) -> GovernanceState:
    catalog_policies = _discover_catalog_policies(client)
    table_tags = _parse_table_tags(
        _rows(client, sql.direct_table_tags_sql(config), ("schema_name", "table_name", "tag_value"))
    )
    column_tags = _parse_column_tags(
        _rows(
            client,
            sql.direct_column_tags_sql(config),
            ("schema_name", "table_name", "column_name", "tag_value"),
        )
    )
    external_selects = _parse_external_selects(
        _rows(
            client,
            sql.existing_consumer_selects_sql(config),
            ("grantee", "table_schema", "table_name"),
        )
    )
    state_tables = _rows(client, sql.governance_state_tables_sql(config), ("table_name",))
    names = {row[0] for row in state_tables if row[0] is not None}
    expected = {sql.MANAGED_GRANTS_TABLE, sql.DEPLOYMENT_STATE_TABLE}
    if names and names != expected:
        raise ConfigError("governance state is partial; both control tables are required")
    if not names:
        return GovernanceState(
            external_selects=external_selects,
            table_tags=table_tags,
            column_tags=column_tags,
            catalog_policies=catalog_policies,
        )
    deployment = _parse_deployment(
        _rows(
            client,
            sql.deployment_state_sql(config),
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
        )
    )
    if deployment is None:
        raise ConfigError("deployment_state table exists without its required singleton row")
    grants = _parse_grants(
        _rows(
            client,
            sql.managed_grants_sql(config),
            ("principal", "table_schema", "table_name", "status", "config_digest"),
        )
    )
    return GovernanceState(
        deployment=deployment,
        grants=grants,
        external_selects=external_selects,
        table_tags=table_tags,
        column_tags=column_tags,
        catalog_policies=catalog_policies,
    )


def classify(config: Config, sources: tuple[SourceTable, ...]) -> tuple[Disposition, ...]:
    overrides = {item.source: item for item in config.overrides}
    unknown = set(overrides) - {source.full_name for source in sources}
    if unknown:
        raise ConfigError("override source(s) were not discovered: " + ", ".join(sorted(unknown)))
    dispositions: list[Disposition] = []
    for source in sorted(sources, key=lambda item: (item.schema, item.table)):
        override = overrides.get(source.full_name)
        if source.column_count == 0:
            if override and override.disposition != "admin_only":
                raise ConfigError(f"{source.full_name} cannot be published without visible columns")
            dispositions.append(Disposition(source, "unavailable", "columns_not_visible"))
            continue
        if override is not None:
            if override.disposition == "workspace_scoped" and source.workspace_id_type != "STRING":
                raise ConfigError(f"{source.full_name} requires STRING workspace_id")
            if override.disposition == "account_shared" and source.workspace_id_type is not None:
                raise ConfigError(
                    f"{source.full_name} has workspace_id and cannot be account_shared"
                )
            dispositions.append(Disposition(source, override.disposition, "explicit_override"))
        elif source.workspace_id_type == "STRING":
            dispositions.append(
                Disposition(source, "workspace_scoped", "string_workspace_id_column")
            )
        else:
            dispositions.append(Disposition(source, "admin_only", "no_string_workspace_id"))
    return tuple(dispositions)


def _validate_state(
    config: Config, state: GovernanceState, sources: tuple[SourceTable, ...]
) -> None:
    deployment = state.deployment
    owned_policy = any(item.name == sql.POLICY_NAME for item in state.catalog_policies)
    if deployment is None:
        if owned_policy:
            raise ConfigError(
                "workspace_scope already exists on system without compatible deployment state"
            )
        if state.grants:
            raise ConfigError("managed grants exist without compatible deployment state")
    else:
        expected = (
            sql.STATE_VERSION,
            config.tags.table_key,
            config.tags.workspace_column_key,
            sql.POLICY_SCOPE,
            sql.POLICY_NAME,
        )
        observed = (
            deployment.state_version,
            deployment.table_tag_key,
            deployment.workspace_column_tag_key,
            deployment.policy_scope,
            deployment.policy_name,
        )
        if observed != expected:
            raise ConfigError("immutable deployment_state is incompatible with this configuration")

    if any(tag.column.casefold() != "workspace_id" for tag in state.column_tags):
        raise ConfigError("workspace column tag is present on a non-workspace_id column")

    source_names = {source.full_name for source in sources}
    protected_modes = {
        tag.full_name: tag.value for tag in state.table_tags if tag.value in _MANAGED_VALUES
    }
    workspace_column_targets = {
        f"system.{tag.schema}.{tag.table}"
        for tag in state.column_tags
        if tag.column.casefold() == "workspace_id"
    }
    for grant in state.grants:
        target = f"system.{grant.schema}.{grant.table}"
        if target not in source_names or target not in protected_modes:
            raise ConfigError("managed grant target is not a discovered tagged system table")
        if protected_modes[target] == "workspace_scoped" and target not in workspace_column_targets:
            raise ConfigError("workspace-scoped managed grant target is missing its column tag")
        if deployment is None:
            raise ConfigError("managed grant cannot be validated without deployment state")
        if grant.status == "PENDING":
            expected_digests = {deployment.pending_config_digest}
        else:
            # activate_managed_grants precedes the final deployment-state update. If that
            # final statement fails, ACTIVE rows legitimately still match the pending digest
            # and must remain recoverable on the next apply.
            expected_digests = {
                deployment.last_successful_config_digest,
                deployment.pending_config_digest,
            }
        expected_digests.discard(None)
        if grant.config_digest not in expected_digests:
            raise ConfigError("managed grant digest does not match its deployment-state phase")


def build_plan(
    config: Config,
    sources: tuple[SourceTable, ...],
    governance_state: GovernanceState | None = None,
) -> Plan:
    state = governance_state or GovernanceState()
    dispositions = classify(config, sources)
    _validate_state(config, state, sources)
    desired = tuple(item for item in dispositions if item.disposition in _MANAGED_VALUES)
    if not desired:
        raise ConfigError("no safely publishable system tables were discovered")

    desired_modes = {item.source.full_name: item.disposition for item in desired}
    stale_workspace_scoped = tuple(
        sorted(
            tag.full_name
            for tag in state.table_tags
            if tag.value == "workspace_scoped" and desired_modes.get(tag.full_name) != tag.value
        )
    )
    stale_account_shared = tuple(
        sorted(
            tag.full_name
            for tag in state.table_tags
            if tag.value == "account_shared" and desired_modes.get(tag.full_name) != tag.value
        )
    )
    desired_grant_tuples = {
        (group.name, item.source.schema, item.source.table)
        for group in config.consumer_groups
        for item in desired
    }
    prior_manifest_keys = {(item.principal, item.schema, item.table) for item in state.grants}
    preserved_external_keys = {
        (item.principal, item.schema, item.table)
        for item in state.external_selects
        if (item.principal, item.schema, item.table) not in prior_manifest_keys
    }
    grant_tuples = tuple(sorted(desired_grant_tuples - preserved_external_keys))
    schemas = tuple(sorted({item.source.schema for item in desired}))

    raw: list[tuple[str, str, str, str | None, tuple[str, ...]]] = [
        (
            "create_governance_catalog",
            config.governance.catalog,
            sql.create_governance_catalog(config),
            None,
            (),
        ),
        (
            "create_governance_schema",
            f"{config.governance.catalog}.{config.governance.schema}",
            sql.create_governance_schema(config),
            None,
            (),
        ),
        (
            "create_managed_grants_state",
            sql.MANAGED_GRANTS_TABLE,
            sql.create_managed_grants_table(config),
            None,
            (),
        ),
        (
            "create_deployment_state",
            sql.DEPLOYMENT_STATE_TABLE,
            sql.create_deployment_state_table(config),
            None,
            (),
        ),
        (
            "initialize_deployment_state",
            sql.DEPLOYMENT_STATE_TABLE,
            sql.initialize_deployment_state(config),
            None,
            (),
        ),
        (
            "acquire_deployment_lock",
            f"{config.governance.catalog}.{config.governance.schema}.{sql.DEPLOYMENT_STATE_TABLE}",
            sql.deployment_lock_plan_marker(config),
            None,
            (),
        ),
    ]
    raw.extend(
        (
            "revoke_prior_managed_select",
            f"system.{grant.schema}.{grant.table}",
            sql.revoke_managed_select(grant.schema, grant.table, grant.principal),
            None,
            (),
        )
        for grant in state.grants
    )
    raw.append(
        (
            "clear_managed_grant_state",
            sql.MANAGED_GRANTS_TABLE,
            sql.clear_managed_grants(config),
            None,
            (),
        )
    )
    table_values = tuple(sorted(_MANAGED_VALUES))
    raw.extend(
        [
            (
                "ensure_governed_tag",
                config.tags.table_key,
                sql.create_governed_tag(config.tags.table_key, table_values),
                config.tags.table_key,
                table_values,
            ),
            (
                "ensure_governed_tag",
                config.tags.workspace_column_key,
                sql.create_governed_tag(config.tags.workspace_column_key),
                config.tags.workspace_column_key,
                (),
            ),
            (
                "create_udf",
                f"{config.governance.catalog}.{config.governance.schema}.workspace_allowed",
                sql.create_udf(config),
                None,
                (),
            ),
        ]
    )
    # Install the policy before assigning policy-selecting tags. Existing external readers
    # therefore move directly from untagged access to filtered access without an unprotected
    # tag-to-policy window.
    raw.append(
        ("create_catalog_policy", "system.workspace_scope", sql.create_policy(config), None, ())
    )
    workspace_sources: list[SourceTable] = []
    for item in desired:
        source = item.source
        if item.disposition == "workspace_scoped":
            # The table tag activates the catalog policy. Bind workspace_id first so an
            # externally granted reader never observes a tagged-but-unfiltered interval.
            raw.append(
                (
                    "set_direct_workspace_column_tag",
                    f"{source.full_name}.workspace_id",
                    sql.set_workspace_column_tag(config, source.schema, source.table),
                    None,
                    (),
                )
            )
            workspace_sources.append(source)
        raw.append(
            (
                "set_direct_table_tag",
                source.full_name,
                sql.set_table_tag(config, source.schema, source.table, item.disposition),
                None,
                (),
            )
        )
    raw.extend(
        (
            "verify_effective_policy",
            source.full_name,
            sql.show_effective_policy(source.schema, source.table),
            None,
            (),
        )
        for source in workspace_sources
    )
    if grant_tuples:
        raw.append(
            (
                "set_pending_deployment_state",
                sql.DEPLOYMENT_STATE_TABLE,
                sql.set_pending_deployment_state(config),
                None,
                (),
            )
        )
        raw.append(
            (
                "record_pending_managed_grants",
                sql.MANAGED_GRANTS_TABLE,
                sql.insert_pending_grants(config, grant_tuples),
                None,
                (),
            )
        )
    raw.extend(
        ("grant_navigation", "system", statement, None, ())
        for statement in sql.grant_navigation(config, schemas)
    )
    raw.extend(
        (
            "grant_direct_select",
            f"system.{schema}.{table}",
            sql.grant_select(schema, table, grantee),
            None,
            (),
        )
        for grantee, schema, table in grant_tuples
    )
    if grant_tuples:
        raw.append(
            (
                "activate_managed_grants",
                sql.MANAGED_GRANTS_TABLE,
                sql.activate_managed_grants(config),
                None,
                (),
            )
        )
    raw.append(
        (
            "upsert_deployment_state",
            sql.DEPLOYMENT_STATE_TABLE,
            sql.upsert_deployment_state(config),
            None,
            (),
        )
    )
    steps = tuple(
        PlanStep(index, kind, target, statement, tag_key, tag_values)
        for index, (kind, target, statement, tag_key, tag_values) in enumerate(raw, 1)
    )
    generated = "\n".join(step.statement.upper() for step in steps)
    if "MATERIALIZED VIEW" in generated or "SCHEDULE EVERY" in generated:
        raise AssertionError("direct-ABAC planner generated copied-data SQL")
    return Plan(
        config.digest,
        config.governance.catalog,
        config.governance.schema,
        dispositions,
        state,
        stale_workspace_scoped,
        stale_account_shared,
        steps,
    )
