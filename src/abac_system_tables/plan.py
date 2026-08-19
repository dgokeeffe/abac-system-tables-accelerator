"""Discovery classification and deterministic mutation planning."""

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
_PRIVILEGE = re.compile(r"^[A-Z][A-Z_]*$")
_MANAGED_VALUES = frozenset({"workspace_scoped", "account_shared"})
_MATERIALIZATION_BACKING = re.compile(
    r"^__materialization_mat_[0-9a-f]{8}(?:_[0-9a-f]{4}){3}_[0-9a-f]{12}_.+_[0-9]+$"
)
_MATERIALIZATION_EVENT_LOG = re.compile(r"^event_log_[0-9a-f]{8}(?:_[0-9a-f]{4}){3}_[0-9a-f]{12}$")


def _is_materialization_support_object(name: str, object_type: str) -> bool:
    """Recognize only Databricks' UUID-named standalone-MV support tables."""
    return object_type.upper() == "MANAGED" and bool(
        _MATERIALIZATION_BACKING.fullmatch(name) or _MATERIALIZATION_EVENT_LOG.fullmatch(name)
    )


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
class FacadeObject:
    name: str
    object_type: str
    managed_disposition: str | None = None


@dataclass(frozen=True, slots=True)
class ExistingGrant:
    object_type: str
    object_name: str
    grantee: str
    privilege: str


@dataclass(frozen=True, slots=True)
class FacadeState:
    objects: tuple[FacadeObject, ...] = ()
    grants: tuple[ExistingGrant, ...] = ()


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
    dispositions: tuple[Disposition, ...]
    facade_state: FacadeState
    steps: tuple[PlanStep, ...]

    @property
    def digest(self) -> str:
        payload = {
            "config_digest": self.config_digest,
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
            "facade_objects": [
                [item.name, item.object_type, item.managed_disposition]
                for item in self.facade_state.objects
            ],
            "facade_grants": [
                [item.object_type, item.object_name, item.grantee, item.privilege]
                for item in self.facade_state.grants
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
            "existingFacadeObjectCount": len(self.facade_state.objects),
            "existingDirectPrivilegeCount": len(self.facade_state.grants),
            "steps": [
                {
                    "order": step.order,
                    "kind": step.kind,
                    "targetRef": "sha256:" + hashlib.sha256(step.target.encode()).hexdigest()[:12],
                }
                for step in self.steps
            ],
        }


def _integer(value: str | None, source: str) -> int:
    try:
        result = int(value or "0")
    except ValueError as exc:
        raise ConfigError(f"discovery returned invalid integer for {source}") from exc
    if result < 0:
        raise ConfigError(f"discovery returned negative integer for {source}")
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


def _rows(
    client: SqlClient, statement: str, expected: tuple[str, ...]
) -> tuple[tuple[str | None, ...], ...]:
    result = client.execute(statement, include_rows=True)
    if result.columns != expected:
        raise ConfigError(f"unexpected facade-state schema: {result.columns!r}")
    if any(len(row) != len(expected) for row in result.rows):
        raise ConfigError("facade-state discovery returned a malformed row")
    return result.rows


def _describe_source(client: SqlClient, source: SourceTable) -> SourceTable:
    """Fill metadata hidden by information_schema for system-shared tables."""
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
    return SourceTable(
        source.schema,
        source.table,
        source.table_type,
        column_count,
        workspace_type,
    )


def discover(client: SqlClient) -> tuple[SourceTable, ...]:
    result = client.execute(sql.discovery_sql(), include_rows=True)
    sources = parse_discovery(result.columns, result.rows)
    return tuple(
        _describe_source(client, source) if source.column_count == 0 else source
        for source in sources
    )


def discover_facade_state(client: SqlClient, config: Config) -> FacadeState:
    object_rows = _rows(client, sql.facade_objects_sql(config), ("table_name", "table_type"))
    tag_rows = _rows(client, sql.facade_tags_sql(config), ("table_name", "tag_value"))
    grant_rows = _rows(
        client,
        sql.facade_grants_sql(config),
        ("object_type", "object_name", "grantee", "privilege_type"),
    )
    tags: dict[str, str] = {}
    for name, value in tag_rows:
        if name is None or value is None or not _IDENTIFIER.fullmatch(name):
            raise ConfigError("unsafe or null facade tag metadata")
        if name in tags:
            raise ConfigError(f"duplicate managed facade tag for {name}")
        tags[name] = value
    objects: list[FacadeObject] = []
    for name, object_type in object_rows:
        if name is None or object_type is None or not _IDENTIFIER.fullmatch(name):
            raise ConfigError("unsafe or null facade object metadata")
        if _is_materialization_support_object(name, object_type):
            if name in tags:
                raise ConfigError("materialization support object must not carry a managed tag")
            continue
        objects.append(FacadeObject(name, object_type.upper(), tags.pop(name, None)))
    if tags:
        raise ConfigError("managed tags refer to facade objects that were not discovered")
    grants: list[ExistingGrant] = []
    for object_type, object_name, grantee, privilege in grant_rows:
        if None in {object_type, object_name, grantee, privilege}:
            raise ConfigError("null facade grant metadata")
        assert object_type is not None and object_name is not None
        assert grantee is not None and privilege is not None
        if object_type not in {"CATALOG", "SCHEMA", "TABLE"} or not _IDENTIFIER.fullmatch(
            object_name
        ):
            raise ConfigError("unsafe facade grant target metadata")
        if not _PRINCIPAL.fullmatch(grantee) or "`" in grantee or ";" in grantee:
            raise ConfigError("unsafe facade grant principal metadata")
        if not _PRIVILEGE.fullmatch(privilege):
            raise ConfigError("facade grant discovery returned an unsafe privilege")
        grants.append(ExistingGrant(object_type, object_name, grantee, privilege))
    return FacadeState(
        tuple(sorted(objects, key=lambda item: item.name)),
        tuple(sorted(grants, key=lambda item: (item.object_type, item.object_name, item.grantee))),
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
                raise ConfigError(
                    f"{source.full_name} has no visible columns and cannot be published safely"
                )
            dispositions.append(Disposition(source, "unavailable", "columns_not_visible"))
            continue
        if override is not None:
            if override.disposition == "workspace_scoped" and source.workspace_id_type != "STRING":
                raise ConfigError(
                    f"{source.full_name} cannot be workspace_scoped without STRING workspace_id"
                )
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


def build_plan(
    config: Config,
    sources: tuple[SourceTable, ...],
    facade_state: FacadeState | None = None,
) -> Plan:
    facade_state = facade_state or FacadeState()
    dispositions = classify(config, sources)
    desired = {
        sql.facade_name(item.source.schema, item.source.table): item
        for item in dispositions
        if item.disposition in _MANAGED_VALUES
    }
    if len(desired) != sum(item.disposition in _MANAGED_VALUES for item in dispositions):
        raise ConfigError("multiple system sources map to the same facade object name")

    stale: list[FacadeObject] = []
    for existing in facade_state.objects:
        if existing.name in desired:
            if existing.object_type != "MATERIALIZED_VIEW":
                raise ConfigError(
                    f"expected managed facade object {existing.name} is not a materialized view"
                )
            if existing.managed_disposition not in {None, *_MANAGED_VALUES}:
                raise ConfigError(
                    f"managed facade object {existing.name} has an unknown disposition tag"
                )
        elif existing.managed_disposition in _MANAGED_VALUES:
            if existing.object_type != "MATERIALIZED_VIEW":
                raise ConfigError(
                    f"stale managed facade object {existing.name} is not a materialized view"
                )
            stale.append(existing)
        else:
            raise ConfigError(f"unexpected object in dedicated facade schema: {existing.name}")

    raw: list[tuple[str, str, str, str | None, tuple[str, ...]]] = [
        ("create_catalog", config.facade.catalog, sql.create_catalog(config), None, ()),
        (
            "create_schema",
            f"{config.facade.catalog}.{config.facade.schema}",
            sql.create_schema(config),
            None,
            (),
        ),
    ]
    trusted = set(config.trusted_principals)
    for grant in facade_state.grants:
        if grant.grantee not in trusted:
            raw.append(
                (
                    "revoke_existing_privilege",
                    f"{grant.object_type}:{grant.object_name}",
                    sql.revoke_grant(
                        config,
                        grant.object_type,
                        grant.object_name,
                        grant.grantee,
                        grant.privilege,
                    ),
                    None,
                    (),
                )
            )
    for item in stale:
        raw.append(
            (
                "drop_stale_materialized_view",
                item.name,
                sql.drop_materialized_view(config, item.name),
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
                f"{config.facade.catalog}.{config.facade.schema}.workspace_allowed",
                sql.create_udf(config),
                None,
                (),
            ),
        ]
    )
    workspace_targets: list[str] = []
    for name, desired_item in sorted(desired.items()):
        source = desired_item.source
        target = f"{config.facade.catalog}.{config.facade.schema}.{name}"
        raw.extend(
            [
                (
                    "create_materialized_view",
                    target,
                    sql.create_materialized_view(config, source.schema, source.table),
                    None,
                    (),
                ),
                (
                    "set_table_tag",
                    target,
                    sql.set_table_tag(
                        config, source.schema, source.table, desired_item.disposition
                    ),
                    None,
                    (),
                ),
            ]
        )
        if desired_item.disposition == "workspace_scoped":
            raw.append(
                (
                    "set_workspace_column_tag",
                    f"{target}.workspace_id",
                    sql.set_workspace_column_tag(config, source.schema, source.table),
                    None,
                    (),
                )
            )
            workspace_targets.append(name)
    raw.append(
        (
            "create_policy",
            f"{config.facade.catalog}.{config.facade.schema}.workspace_scope",
            sql.create_policy(config),
            None,
            (),
        )
    )
    for name in workspace_targets:
        raw.append(
            ("verify_effective_policy", name, sql.show_effective_policy(config, name), None, ())
        )
    raw.extend(
        ("grant", "facade", statement, None, ())
        for statement in sql.grants(config, tuple(sorted(desired)))
    )
    steps = tuple(
        PlanStep(index, kind, target, statement, tag_key, tag_values)
        for index, (kind, target, statement, tag_key, tag_values) in enumerate(raw, 1)
    )
    if any(
        " ON CATALOG `system`" in step.statement or " ON SCHEMA `system`." in step.statement
        for step in steps
    ):
        raise AssertionError("planner generated a forbidden system grant")
    return Plan(config.digest, dispositions, facade_state, steps)
