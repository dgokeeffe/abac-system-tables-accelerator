from __future__ import annotations

import json
from pathlib import Path

from abac_system_tables.cli import main
from abac_system_tables.client import StatementError, StatementResult
from tests.helpers import FakeClient, valid_config_text

DISCOVERY_COLUMNS = (
    "table_schema",
    "table_name",
    "table_type",
    "column_count",
    "workspace_id_type",
)


def discovery_client() -> FakeClient:
    def handler(statement: str, _rows: bool) -> StatementResult:
        if "table_catalog = 'system'" in statement:
            return StatementResult(
                "d",
                "SUCCEEDED",
                DISCOVERY_COLUMNS,
                (("access", "audit", "MANAGED", "17", "STRING"),),
            )
        if "table_tags" in statement:
            return StatementResult("t", "SUCCEEDED", ("table_name", "tag_value"), ())
        if "schema_privileges" in statement:
            return StatementResult(
                "g", "SUCCEEDED", ("object_type", "object_name", "grantee", "privilege_type"), ()
            )
        return StatementResult("o", "SUCCEEDED", ("table_name", "table_type"), ())

    return FakeClient(handler)


def test_plan_cli_is_read_only_redacted_and_discovers_state(tmp_path: Path, capsys: object) -> None:
    config = tmp_path / "config.json"
    config.write_text(valid_config_text())
    client = discovery_client()
    result = main(
        ["plan", "--config", str(config), "--profile", "admin", "--warehouse-id", "warehouse"],
        client_factory=lambda _p, _w: client,
    )
    assert result == 0
    output = capsys.readouterr().out  # type: ignore[attr-defined]
    payload = json.loads(output)
    assert payload["planDigest"] and '"111"' not in output and "bu_alpha" not in output
    assert len(client.calls) == 4
    assert all(
        not any(
            word in statement.upper()
            for word in ("CREATE ", "ALTER ", "GRANT ", "REVOKE ", "DROP ")
        )
        for statement, _ in client.calls
    )


def test_apply_wrong_plan_confirmation_does_not_mutate(tmp_path: Path, capsys: object) -> None:
    config = tmp_path / "config.json"
    config.write_text(valid_config_text())
    client = discovery_client()
    result = main(
        [
            "apply",
            "--config",
            str(config),
            "--profile",
            "admin",
            "--warehouse-id",
            "warehouse",
            "--confirm",
            "wrong",
        ],
        client_factory=lambda _p, _w: client,
    )
    assert result == 2
    assert "tenant row data" in capsys.readouterr().err  # type: ignore[attr-defined]
    assert len(client.calls) == 4


def test_verify_cli_requires_config_and_redacts(tmp_path: Path, capsys: object) -> None:
    config = tmp_path / "config.json"
    config.write_text(valid_config_text())
    scenarios = tmp_path / "verify.json"
    scenarios.write_text(
        json.dumps(
            {
                "version": 1,
                "scenarios": [
                    {
                        "name": "secret-scenario",
                        "profile": "secret-profile",
                        "expected_identity": "sp",
                        "consumer_group": "bu_alpha",
                        "checks": [
                            {
                                "relation": "facade_catalog.published.access__audit",
                                "expectation": "scoped",
                            }
                        ],
                    }
                ],
            }
        )
    )

    def handler(statement: str, _rows: bool) -> StatementResult:
        if statement.startswith("SELECT current_user"):
            return StatementResult(
                "i", "SUCCEEDED", ("current_identity", "session_identity"), (("sp", "sp"),)
            )
        if "consumer_member" in statement:
            return StatementResult(
                "m",
                "SUCCEEDED",
                ("consumer_member", "trusted_member_0", "trusted_member_1"),
                (("true", "false", "false"),),
            )
        return StatementResult(
            "q", "SUCCEEDED", ("observed_count", "violation_count"), (("2", "0"),)
        )

    result = main(
        [
            "verify",
            "--config",
            str(config),
            "--scenarios",
            str(scenarios),
            "--warehouse-id",
            "warehouse",
        ],
        client_factory=lambda _p, _w: FakeClient(handler),
    )
    assert result == 0
    output = capsys.readouterr().out  # type: ignore[attr-defined]
    assert (
        "secret-scenario" not in output
        and "secret-profile" not in output
        and "facade_catalog" not in output
    )


def test_platform_failure_is_redacted(tmp_path: Path, capsys: object) -> None:
    config = tmp_path / "config.json"
    config.write_text(valid_config_text())
    client = FakeClient(
        lambda _s, _r: (_ for _ in ()).throw(StatementError("sensitive tenant detail"))
    )
    assert (
        main(
            ["plan", "--config", str(config), "--profile", "admin", "--warehouse-id", "w"],
            client_factory=lambda _p, _w: client,
        )
        == 2
    )
    assert "sensitive" not in capsys.readouterr().err  # type: ignore[attr-defined]
