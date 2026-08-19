"""Strict desired-state and verification configuration parsing."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_WORKSPACE_ID = re.compile(r"^[0-9]{1,32}$")
_PRINCIPAL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 @._+:/-]{0,254}$")
_RELATION = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]{0,127}\.[A-Za-z_][A-Za-z0-9_]{0,127}"
    r"\.[A-Za-z_][A-Za-z0-9_]{0,127}$"
)
_SECRET_KEY = re.compile(
    r"(^|_)(token|password|passwd|secret|client_secret|private_key|access_key)($|_)", re.I
)
_SECRET_VALUE = re.compile(
    r"(-----BEGIN [A-Z ]*PRIVATE KEY-----|\bBearer\s+[A-Za-z0-9._~-]+|\bdapi[a-zA-Z0-9]{16,})"
)
_DISPOSITIONS = frozenset({"workspace_scoped", "account_shared", "admin_only"})


class ConfigError(ValueError):
    """The configuration is unsafe or invalid."""


def _fail(path: str, message: str) -> NoReturn:
    raise ConfigError(f"{path}: {message}")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ConfigError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _object(value: Any, path: str, allowed: set[str], required: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(path, "must be an object")
    unknown = set(value) - allowed
    missing = required - set(value)
    if unknown:
        _fail(path, f"unknown field(s): {', '.join(sorted(unknown))}")
    if missing:
        _fail(path, f"missing field(s): {', '.join(sorted(missing))}")
    return value


def _string(value: Any, path: str, *, minimum: int = 1) -> str:
    if not isinstance(value, str) or len(value.strip()) < minimum or value != value.strip():
        _fail(path, f"must be a trimmed string of at least {minimum} character(s)")
    if any(ord(char) < 32 for char in value):
        _fail(path, "must not contain control characters")
    return value


def _identifier(value: Any, path: str) -> str:
    text = _string(value, path)
    if not _IDENTIFIER.fullmatch(text):
        _fail(path, "must be a simple Unity Catalog identifier")
    return text


def _principal(value: Any, path: str) -> str:
    text = _string(value, path)
    if not _PRINCIPAL.fullmatch(text) or "`" in text or ";" in text:
        _fail(path, "must be a safe account principal name")
    return text


def _workspace_id(value: Any, path: str) -> str:
    text = _string(value, path)
    if not _WORKSPACE_ID.fullmatch(text):
        _fail(path, "must be a decimal workspace ID string")
    return text


def _list(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        _fail(path, "must be an array")
    return value


def _unique(items: list[str], path: str) -> tuple[str, ...]:
    if len(items) != len(set(items)):
        _fail(path, "must not contain duplicates")
    return tuple(items)


def _reject_secrets(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if _SECRET_KEY.search(key):
                _fail(f"{path}.{key}", "secret-shaped fields are forbidden")
            _reject_secrets(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_secrets(child, f"{path}[{index}]")
    elif isinstance(value, str) and _SECRET_VALUE.search(value):
        _fail(path, "secret-shaped values are forbidden")


@dataclass(frozen=True, slots=True)
class Facade:
    catalog: str
    schema: str
    refresh_every_hours: int


@dataclass(frozen=True, slots=True)
class Tags:
    table_key: str
    workspace_column_key: str


@dataclass(frozen=True, slots=True)
class ConsumerGroup:
    name: str
    workspace_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Override:
    source: str
    disposition: str
    rationale: str | None


@dataclass(frozen=True, slots=True)
class Config:
    version: int
    facade: Facade
    tags: Tags
    consumer_groups: tuple[ConsumerGroup, ...]
    trusted_principals: tuple[str, ...]
    overrides: tuple[Override, ...]

    @property
    def canonical(self) -> str:
        payload = {
            "consumer_groups": [
                {"name": group.name, "workspace_ids": list(group.workspace_ids)}
                for group in self.consumer_groups
            ],
            "facade": {
                "catalog": self.facade.catalog,
                "refresh_every_hours": self.facade.refresh_every_hours,
                "schema": self.facade.schema,
            },
            "overrides": [
                {
                    "disposition": item.disposition,
                    **({"rationale": item.rationale} if item.rationale is not None else {}),
                    "source": item.source,
                }
                for item in self.overrides
            ],
            "tags": {
                "table_key": self.tags.table_key,
                "workspace_column_key": self.tags.workspace_column_key,
            },
            "trusted_principals": list(self.trusted_principals),
            "version": self.version,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.canonical.encode()).hexdigest()


def loads_config(text: str) -> Config:
    """Parse a strict JSON desired-state document."""
    try:
        raw = json.loads(text, object_pairs_hook=_pairs)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"invalid JSON: {exc.msg}") from exc
    _reject_secrets(raw)
    root = _object(
        raw,
        "$",
        {"version", "facade", "tags", "consumer_groups", "trusted_principals", "overrides"},
        {"version", "facade", "tags", "consumer_groups", "trusted_principals"},
    )
    if type(root["version"]) is not int or root["version"] != 1:
        _fail("$.version", "must equal 1")

    facade_raw = _object(
        root["facade"],
        "$.facade",
        {"catalog", "schema", "refresh_every_hours"},
        {"catalog", "schema", "refresh_every_hours"},
    )
    hours = facade_raw["refresh_every_hours"]
    if type(hours) is not int or not 1 <= hours <= 168:
        _fail("$.facade.refresh_every_hours", "must be an integer from 1 to 168")
    facade = Facade(
        catalog=_identifier(facade_raw["catalog"], "$.facade.catalog"),
        schema=_identifier(facade_raw["schema"], "$.facade.schema"),
        refresh_every_hours=hours,
    )
    if facade.catalog.lower() in {"system", "samples", "__databricks_internal", "hive_metastore"}:
        _fail("$.facade.catalog", "must be a separate, non-reserved facade catalog")
    if facade.schema.lower() == "information_schema":
        _fail("$.facade.schema", "must not use the reserved information_schema name")

    tags_raw = _object(
        root["tags"],
        "$.tags",
        {"table_key", "workspace_column_key"},
        {"table_key", "workspace_column_key"},
    )
    tags = Tags(
        table_key=_identifier(tags_raw["table_key"], "$.tags.table_key"),
        workspace_column_key=_identifier(
            tags_raw["workspace_column_key"], "$.tags.workspace_column_key"
        ),
    )
    if tags.table_key == tags.workspace_column_key:
        _fail("$.tags", "table and column tag keys must differ")

    groups_raw = _list(root["consumer_groups"], "$.consumer_groups")
    if not groups_raw:
        _fail("$.consumer_groups", "must contain at least one account group")
    groups: list[ConsumerGroup] = []
    for index, value in enumerate(groups_raw):
        path = f"$.consumer_groups[{index}]"
        item = _object(value, path, {"name", "workspace_ids"}, {"name", "workspace_ids"})
        ids = [
            _workspace_id(entry, f"{path}.workspace_ids[{item_index}]")
            for item_index, entry in enumerate(
                _list(item["workspace_ids"], f"{path}.workspace_ids")
            )
        ]
        if not ids:
            _fail(f"{path}.workspace_ids", "must not be empty")
        groups.append(
            ConsumerGroup(
                name=_principal(item["name"], f"{path}.name"),
                workspace_ids=_unique(ids, f"{path}.workspace_ids"),
            )
        )
    _unique([group.name for group in groups], "$.consumer_groups[].name")

    trusted = _unique(
        [
            _principal(entry, f"$.trusted_principals[{index}]")
            for index, entry in enumerate(_list(root["trusted_principals"], "$.trusted_principals"))
        ],
        "$.trusted_principals",
    )
    if not trusted:
        _fail("$.trusted_principals", "must include at least one trusted admin or run-as principal")
    if any(item.casefold() == "account users" for item in trusted):
        _fail("$.trusted_principals", "must not exempt the broad account users principal")
    overlap = set(trusted) & {group.name for group in groups}
    if overlap:
        _fail("$", f"consumer and trusted principals overlap: {', '.join(sorted(overlap))}")
    # The ABAC policy targets `account users`; only exemptions consume its remaining
    # principal quota. Consumer groups are evaluated inside the fail-closed UDF.
    if len(trusted) + 1 > 20:
        _fail("$.trusted_principals", "policy principal limit allows at most 19 exemptions")

    overrides: list[Override] = []
    for index, value in enumerate(_list(root.get("overrides", []), "$.overrides")):
        path = f"$.overrides[{index}]"
        item = _object(
            value,
            path,
            {"source", "disposition", "rationale"},
            {"source", "disposition"},
        )
        source = _string(item["source"], f"{path}.source")
        parts = source.split(".")
        if (
            len(parts) != 3
            or parts[0] != "system"
            or any(not _IDENTIFIER.fullmatch(part) for part in parts)
        ):
            _fail(f"{path}.source", "must be system.<schema>.<table>")
        disposition = _string(item["disposition"], f"{path}.disposition")
        if disposition not in _DISPOSITIONS:
            _fail(f"{path}.disposition", "is not a supported disposition")
        rationale_raw = item.get("rationale")
        rationale = (
            _string(rationale_raw, f"{path}.rationale", minimum=20)
            if rationale_raw is not None
            else None
        )
        if disposition == "account_shared" and rationale is None:
            _fail(f"{path}.rationale", "is mandatory for account_shared")
        if disposition != "account_shared" and rationale is not None:
            _fail(f"{path}.rationale", "is only allowed for account_shared")
        overrides.append(Override(source, disposition, rationale))
    _unique([item.source for item in overrides], "$.overrides[].source")

    return Config(1, facade, tags, tuple(groups), trusted, tuple(overrides))


def load_config(path: Path) -> Config:
    return loads_config(path.read_text(encoding="utf-8"))


@dataclass(frozen=True, slots=True)
class VerifyCheck:
    relation: str
    expectation: str


@dataclass(frozen=True, slots=True)
class VerifyScenario:
    name: str
    profile: str
    expected_identity: str
    consumer_group: str
    checks: tuple[VerifyCheck, ...]


@dataclass(frozen=True, slots=True)
class VerifyConfig:
    version: int
    scenarios: tuple[VerifyScenario, ...]


def loads_verify_config(text: str) -> VerifyConfig:
    """Parse strict representative-principal verification scenarios."""
    try:
        raw = json.loads(text, object_pairs_hook=_pairs)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"invalid JSON: {exc.msg}") from exc
    _reject_secrets(raw)
    root = _object(raw, "$", {"version", "scenarios"}, {"version", "scenarios"})
    if type(root["version"]) is not int or root["version"] != 1:
        _fail("$.version", "must equal 1")
    scenarios: list[VerifyScenario] = []
    for index, value in enumerate(_list(root["scenarios"], "$.scenarios")):
        path = f"$.scenarios[{index}]"
        item = _object(
            value,
            path,
            {"name", "profile", "expected_identity", "consumer_group", "checks"},
            {"name", "profile", "expected_identity", "consumer_group", "checks"},
        )
        checks: list[VerifyCheck] = []
        for check_index, check_value in enumerate(_list(item["checks"], f"{path}.checks")):
            check_path = f"{path}.checks[{check_index}]"
            check = _object(
                check_value,
                check_path,
                {"relation", "expectation"},
                {"relation", "expectation"},
            )
            relation = _string(check["relation"], f"{check_path}.relation")
            if not _RELATION.fullmatch(relation):
                _fail(f"{check_path}.relation", "must be a safe three-part relation")
            expectation = _string(check["expectation"], f"{check_path}.expectation")
            if expectation not in {"scoped", "shared", "denied"}:
                _fail(f"{check_path}.expectation", "must be scoped, shared, or denied")
            checks.append(VerifyCheck(relation, expectation))
        if not checks:
            _fail(f"{path}.checks", "must not be empty")
        scenarios.append(
            VerifyScenario(
                _string(item["name"], f"{path}.name"),
                _string(item["profile"], f"{path}.profile"),
                _string(item["expected_identity"], f"{path}.expected_identity"),
                _principal(item["consumer_group"], f"{path}.consumer_group"),
                tuple(checks),
            )
        )
    if not scenarios:
        _fail("$.scenarios", "must not be empty")
    _unique([scenario.name for scenario in scenarios], "$.scenarios[].name")
    return VerifyConfig(1, tuple(scenarios))
