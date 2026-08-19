from __future__ import annotations

import json

import pytest

from abac_system_tables.client import StatementError, StatementResult
from abac_system_tables.config import ConfigError, loads_config
from abac_system_tables.plan import (
    ExistingGrant,
    FacadeObject,
    FacadeState,
    SourceTable,
    build_plan,
    classify,
    discover,
    discover_facade_state,
    parse_discovery,
)
from tests.helpers import FakeClient, valid_config_data, valid_config_text


def sources() -> tuple[SourceTable, ...]:
    return (
        SourceTable("access", "audit", "MANAGED", 17, "STRING"),
        SourceTable("billing", "list_prices", "MANAGED", 8, None),
        SourceTable("compute", "hidden", "MANAGED", 0, None),
    )


def test_parse_and_discover_require_exact_safe_metadata() -> None:
    columns = ("table_schema", "table_name", "table_type", "column_count", "workspace_id_type")
    parsed = parse_discovery(columns, (("access", "audit", "MANAGED", "17", "string"),))
    assert parsed[0].workspace_id_type == "STRING"
    with pytest.raises(ConfigError, match="unexpected discovery schema"):
        parse_discovery(("wrong",), ())
    with pytest.raises(ConfigError, match="unsafe source identifier"):
        parse_discovery(columns, (("bad;schema", "audit", "MANAGED", "1", "STRING"),))
    client = FakeClient(
        lambda _s, _r: StatementResult(
            "id", "SUCCEEDED", columns, (("a", "b", "M", "1", "STRING"),)
        )
    )
    assert discover(client)[0].full_name == "system.a.b"


def test_discovery_falls_back_to_describe_for_shared_system_tables() -> None:
    columns = ("table_schema", "table_name", "table_type", "column_count", "workspace_id_type")

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

    enriched = discover(FakeClient(handler))
    assert enriched == (SourceTable("alert", "alerts", "MANAGED", 2, "STRING"),)

    def denied(statement: str, rows: bool) -> StatementResult:
        if statement.startswith("WITH source_tables"):
            return handler(statement, rows)
        raise StatementError("denied", error_code="PERMISSION_DENIED")

    unavailable = discover(FakeClient(denied))
    assert unavailable[0].column_count == 0


def test_facade_state_discovery_parses_objects_tags_and_grants() -> None:
    config = loads_config(valid_config_text())

    def handler(statement: str, _rows: bool) -> StatementResult:
        if "information_schema.tables" in statement:
            return StatementResult(
                "o",
                "SUCCEEDED",
                ("table_name", "table_type"),
                (
                    ("access__audit", "MATERIALIZED_VIEW"),
                    (
                        "__materialization_mat_12345678_1234_1234_1234_123456789abc_access__audit_1",
                        "MANAGED",
                    ),
                    ("event_log_12345678_1234_1234_1234_123456789abc", "MANAGED"),
                ),
            )
        if "table_tags" in statement:
            return StatementResult(
                "t",
                "SUCCEEDED",
                ("table_name", "tag_value"),
                (("access__audit", "workspace_scoped"),),
            )
        return StatementResult(
            "g",
            "SUCCEEDED",
            ("object_type", "object_name", "grantee", "privilege_type"),
            (("TABLE", "access__audit", "old_group", "SELECT"),),
        )

    state = discover_facade_state(FakeClient(handler), config)
    assert state.objects == (
        FacadeObject("access__audit", "MATERIALIZED_VIEW", "workspace_scoped"),
    )
    assert state.grants[0].grantee == "old_group"


def test_default_and_overridden_dispositions_fail_closed() -> None:
    assert [d.disposition for d in classify(loads_config(valid_config_text()), sources())] == [
        "workspace_scoped",
        "admin_only",
        "unavailable",
    ]
    data = valid_config_data()
    data["overrides"] = [
        {
            "source": "system.billing.list_prices",
            "disposition": "account_shared",
            "rationale": "Global reference with no workspace-specific tenant row scope.",
        }
    ]
    assert classify(loads_config(json.dumps(data)), sources())[1].disposition == "account_shared"
    data["overrides"] = [
        {
            "source": "system.access.audit",
            "disposition": "account_shared",
            "rationale": "Unsafe attempt with enough words to pass rationale validation.",
        }
    ]
    with pytest.raises(ConfigError, match="cannot be account_shared"):
        classify(loads_config(json.dumps(data)), sources())


def test_plan_reconciles_removed_and_direct_grants_before_replace() -> None:
    config = loads_config(valid_config_text())
    state = FacadeState(
        (
            FacadeObject("access__audit", "MATERIALIZED_VIEW", "workspace_scoped"),
            FacadeObject("old__gone", "MATERIALIZED_VIEW", "workspace_scoped"),
        ),
        (
            ExistingGrant("CATALOG", "facade_catalog", "catalog_reader", "ALL_PRIVILEGES"),
            ExistingGrant("SCHEMA", "published", "removed_group", "SELECT"),
            ExistingGrant("TABLE", "access__audit", "bu_alpha", "SELECT"),
            ExistingGrant("SCHEMA", "published", "facade_admins", "SELECT"),
        ),
    )
    plan = build_plan(config, sources(), state)
    kinds = [s.kind for s in plan.steps]
    assert kinds.count("revoke_existing_privilege") == 3
    assert "drop_stale_materialized_view" in kinds
    assert max(i for i, k in enumerate(kinds) if k == "revoke_existing_privilege") < kinds.index(
        "create_materialized_view"
    )
    assert kinds.index("verify_effective_policy") < kinds.index("grant")
    assert "TO `account users`" in next(
        s.statement for s in plan.steps if s.kind == "create_policy"
    )


def test_scoped_to_admin_unavailable_or_absent_retires_managed_mv() -> None:
    config = loads_config(valid_config_text())
    state = FacadeState(
        (FacadeObject("access__audit", "MATERIALIZED_VIEW", "workspace_scoped"),), ()
    )
    for changed in (
        (SourceTable("access", "audit", "MANAGED", 17, None),),
        (SourceTable("access", "audit", "MANAGED", 0, None),),
        (),
    ):
        assert any(
            s.kind == "drop_stale_materialized_view"
            for s in build_plan(config, changed, state).steps
        )


def test_unexpected_object_blocks_and_plan_digest_binds_state() -> None:
    config = loads_config(valid_config_text())
    with pytest.raises(ConfigError, match="unexpected object"):
        build_plan(
            config, sources(), FacadeState((FacadeObject("unrelated", "MANAGED", None),), ())
        )
    first = build_plan(config, sources(), FacadeState())
    second = build_plan(
        config, sources(), FacadeState((), (ExistingGrant("SCHEMA", "published", "old", "SELECT"),))
    )
    assert first.digest != second.digest
    output = json.dumps(first.redacted())
    assert "bu_alpha" not in output and '"111"' not in output and "facade_catalog" not in output


def test_collision_and_unknown_override_fail() -> None:
    config = loads_config(valid_config_text())
    with pytest.raises(ConfigError, match="same facade"):
        build_plan(
            config,
            (
                SourceTable("a", "b__c", "M", 1, "STRING"),
                SourceTable("a__b", "c", "M", 1, "STRING"),
            ),
        )
    data = valid_config_data()
    data["overrides"] = [{"source": "system.x.y", "disposition": "admin_only"}]
    with pytest.raises(ConfigError, match="not discovered"):
        classify(loads_config(json.dumps(data)), sources())
