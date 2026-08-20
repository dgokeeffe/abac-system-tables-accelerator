from __future__ import annotations

import re

import pytest

from abac_system_tables.apply import ApplyError, apply_plan, validate_identity
from abac_system_tables.client import StatementError, StatementResult
from abac_system_tables.config import loads_config
from abac_system_tables.plan import SourceTable, build_plan
from tests.helpers import FakeClient, valid_config_text


def sample_plan():
    return build_plan(
        loads_config(valid_config_text()),
        (SourceTable("access", "audit", "MANAGED", 17, "STRING"),),
    )


def handler_factory(
    *,
    policy_after: int = 1,
    extra_tag: bool = False,
    existing_lease: str | None = None,
    lease_stale: bool = False,
):
    policy_calls = 0
    lease_token: str | None = existing_lease

    def handler(statement: str, _rows: bool) -> StatementResult:
        nonlocal policy_calls, lease_token
        if statement.startswith("SELECT current_user"):
            return StatementResult(
                "i", "SUCCEEDED", ("current_identity", "session_identity"), (("admin", "admin"),)
            )
        if "SET lease_token = '" in statement and "lease_token IS NULL" in statement:
            match = re.search(r"SET lease_token = '([0-9a-f]{32})'", statement)
            assert match is not None
            if lease_token is None or lease_stale:
                lease_token = match.group(1)
            return StatementResult("lock", "SUCCEEDED")
        if statement.startswith("SELECT lease_token"):
            return StatementResult("lock-status", "SUCCEEDED", ("lease_token",), ((lease_token,),))
        if "SET lease_acquired_at = current_timestamp()" in statement:
            return StatementResult("renew", "SUCCEEDED")
        if "SET lease_token = NULL" in statement:
            match = re.search(r"lease_token = '([0-9a-f]{32})'", statement)
            if match is not None and lease_token == match.group(1):
                lease_token = None
            return StatementResult("release", "SUCCEEDED")
        if statement == "SHOW GOVERNED TAGS":
            return StatementResult(
                "s",
                "SUCCEEDED",
                ("tag_name",),
                (("system_table_scope",), ("workspace_scope_column",)),
            )
        if statement.startswith("DESCRIBE GOVERNED TAG"):
            values = "[]"
            if "system_table_scope" in statement:
                values = (
                    '["account_shared", "workspace_scoped"'
                    + (', "extra"' if extra_tag else "")
                    + "]"
                )
            return StatementResult(
                "d", "SUCCEEDED", ("info_name", "info_value"), (("Allowed Values", values),)
            )
        if statement.startswith("SHOW EFFECTIVE POLICIES"):
            policy_calls += 1
            rows = (("workspace_scope", "ROW_FILTER"),) if policy_calls >= policy_after else ()
            return StatementResult("p", "SUCCEEDED", ("policy_name", "policy_type"), rows)
        return StatementResult("statement", "SUCCEEDED")

    return handler


def test_apply_requires_exact_plan_confirmation_and_identity() -> None:
    plan = sample_plan()
    client = FakeClient(handler_factory())
    with pytest.raises(ApplyError, match="plan digest"):
        apply_plan(client, plan, plan.config_digest)
    assert client.calls == []
    applied = apply_plan(client, plan, plan.digest, policy_attempts=1, policy_interval_seconds=0)
    assert len(applied) == len(plan.steps)
    assert all(item.state == "SUCCEEDED" for item in applied)
    assert any("lease_token IS NULL" in statement for statement, _ in client.calls)
    assert any("SET lease_token = NULL" in statement for statement, _ in client.calls)
    assert any(
        "SET lease_acquired_at = current_timestamp()" in statement for statement, _ in client.calls
    )
    mismatch = FakeClient(
        lambda _s, _r: StatementResult(
            "i", "SUCCEEDED", ("current_identity", "session_identity"), (("one", "two"),)
        )
    )
    with pytest.raises(ApplyError, match="differs"):
        validate_identity(mismatch)


def test_deployment_lease_loser_fails_before_governance_mutation() -> None:
    plan = sample_plan()
    client = FakeClient(handler_factory(existing_lease="f" * 32))
    with pytest.raises(ApplyError, match="lease could not be acquired"):
        apply_plan(client, plan, plan.digest, policy_attempts=1, policy_interval_seconds=0)
    lock_index = next(
        index
        for index, (statement, _) in enumerate(client.calls)
        if "lease_token IS NULL" in statement
    )
    assert not any(
        statement.startswith("REVOKE SELECT") or statement.startswith("ALTER TABLE `system`")
        for statement, _ in client.calls[lock_index + 1 :]
    )


def test_failed_lease_proof_releases_candidate_token() -> None:
    plan = sample_plan()
    acquired = False

    def handler(statement: str, _rows: bool) -> StatementResult:
        nonlocal acquired
        if statement.startswith("SELECT current_user"):
            return StatementResult(
                "identity",
                "SUCCEEDED",
                ("current_identity", "session_identity"),
                (("admin", "admin"),),
            )
        if "SET lease_token = '" in statement and "lease_token IS NULL" in statement:
            acquired = True
            return StatementResult("acquire", "SUCCEEDED")
        if statement.startswith("SELECT lease_token") and acquired:
            raise StatementError("transient proof failure")
        if "SET lease_token = NULL" in statement:
            return StatementResult("release", "SUCCEEDED")
        return StatementResult("other", "SUCCEEDED")

    client = FakeClient(handler)
    with pytest.raises(ApplyError, match="lease could not be acquired"):
        apply_plan(client, plan, plan.digest, policy_attempts=1, policy_interval_seconds=0)
    assert any("SET lease_token = NULL" in statement for statement, _ in client.calls)


def test_stale_deployment_lease_is_recovered() -> None:
    plan = sample_plan()
    client = FakeClient(handler_factory(existing_lease="e" * 32, lease_stale=True))
    applied = apply_plan(client, plan, plan.digest, policy_attempts=1, policy_interval_seconds=0)
    assert len(applied) == len(plan.steps)
    acquire = next(statement for statement, _ in client.calls if "lease_token IS NULL" in statement)
    assert f"INTERVAL {30} MINUTES" in acquire


def test_deployment_lease_releases_on_ordinary_failure() -> None:
    plan = sample_plan()
    base = handler_factory()

    def handler(statement: str, rows: bool) -> StatementResult:
        if statement.startswith("CREATE OR REPLACE FUNCTION"):
            raise StatementError("injected failure")
        return base(statement, rows)

    client = FakeClient(handler)
    with pytest.raises(ApplyError):
        apply_plan(client, plan, plan.digest, policy_attempts=1, policy_interval_seconds=0)
    assert any("SET lease_token = NULL" in statement for statement, _ in client.calls)


def test_interrupt_after_acquisition_releases_lease() -> None:
    plan = sample_plan()
    base = handler_factory()

    def handler(statement: str, rows: bool) -> StatementResult:
        if statement.startswith("CREATE OR REPLACE FUNCTION"):
            raise KeyboardInterrupt()
        return base(statement, rows)

    client = FakeClient(handler)
    with pytest.raises(KeyboardInterrupt):
        apply_plan(client, plan, plan.digest, policy_attempts=1, policy_interval_seconds=0)
    assert any("SET lease_token = NULL" in statement for statement, _ in client.calls)


def test_system_exit_after_acquisition_releases_lease() -> None:
    plan = sample_plan()
    base = handler_factory()

    def handler(statement: str, rows: bool) -> StatementResult:
        if statement.startswith("CREATE OR REPLACE FUNCTION"):
            raise SystemExit("test exit")
        return base(statement, rows)

    client = FakeClient(handler)
    with pytest.raises(SystemExit, match="test exit"):
        apply_plan(client, plan, plan.digest, policy_attempts=1, policy_interval_seconds=0)
    assert any("SET lease_token = NULL" in statement for statement, _ in client.calls)


def test_policy_gate_allows_delayed_success_and_times_out_closed() -> None:
    plan = sample_plan()
    client = FakeClient(handler_factory(policy_after=2))
    apply_plan(client, plan, plan.digest, policy_attempts=2, policy_interval_seconds=0)
    assert sum(s.startswith("SHOW EFFECTIVE") for s, _ in client.calls) == 2
    with pytest.raises(ApplyError, match="remains closed"):
        apply_plan(
            FakeClient(handler_factory(policy_after=99)),
            plan,
            plan.digest,
            policy_attempts=2,
            policy_interval_seconds=0,
        )


def test_conflicting_effective_row_filter_blocks_before_grants() -> None:
    plan = sample_plan()
    base_handler = handler_factory()

    def handler(statement: str, rows: bool) -> StatementResult:
        if statement.startswith("SHOW EFFECTIVE POLICIES"):
            return StatementResult(
                "p",
                "SUCCEEDED",
                ("policy_name", "policy_type"),
                (("workspace_scope", "ROW_FILTER"), ("foreign_scope", "ROW_FILTER")),
            )
        return base_handler(statement, rows)

    client = FakeClient(handler)
    with pytest.raises(ApplyError, match="remains closed"):
        apply_plan(client, plan, plan.digest, policy_attempts=1, policy_interval_seconds=0)
    assert not any(statement.startswith("GRANT SELECT") for statement, _ in client.calls)


def test_policy_gate_accepts_databricks_title_case_columns() -> None:
    base_handler = handler_factory()

    def handler(statement: str, rows: bool) -> StatementResult:
        result = base_handler(statement, rows)
        if statement.startswith("SHOW EFFECTIVE POLICIES"):
            return StatementResult(
                "p",
                "SUCCEEDED",
                ("Policy Name", "Policy Type", "Catalog", "Schema", "Table", "Comment"),
                (("workspace_scope", "ROW_FILTER", "system", "", None, ""),),
            )
        return result

    plan = sample_plan()
    assert apply_plan(
        FakeClient(handler), plan, plan.digest, policy_attempts=1, policy_interval_seconds=0
    )


def test_existing_tag_requires_exact_allowed_value_set() -> None:
    plan = sample_plan()
    with pytest.raises(ApplyError, match="incompatible allowed-value set"):
        apply_plan(
            FakeClient(handler_factory(extra_tag=True)),
            plan,
            plan.digest,
            policy_attempts=1,
            policy_interval_seconds=0,
        )


def test_governed_tag_listing_accepts_databricks_title_case_columns() -> None:
    base_handler = handler_factory()

    def handler(statement: str, rows: bool) -> StatementResult:
        result = base_handler(statement, rows)
        if statement == "SHOW GOVERNED TAGS":
            return StatementResult(
                "s",
                "SUCCEEDED",
                ("Tag Key", "Id", "Description", "Values", "Create Time", "Update Time"),
                (
                    (
                        "system_table_scope",
                        "id-1",
                        "managed",
                        '["account_shared", "workspace_scoped"]',
                        "",
                        "",
                    ),
                    ("workspace_scope_column", "id-2", "managed", "[]", "", ""),
                ),
            )
        return result

    plan = sample_plan()
    applied = apply_plan(
        FakeClient(handler), plan, plan.digest, policy_attempts=1, policy_interval_seconds=0
    )
    assert len(applied) == len(plan.steps)


def test_create_tag_race_is_only_accepted_with_exact_description() -> None:
    plan = sample_plan()
    base_handler = handler_factory()

    def handler(statement: str, rows: bool) -> StatementResult:
        if (
            statement.startswith("SELECT current_user")
            or statement.startswith("SELECT lease_token")
            or "lease_token" in statement
            or "lease_acquired_at" in statement
        ):
            return base_handler(statement, rows)
        if statement == "SHOW GOVERNED TAGS":
            return StatementResult("s", "SUCCEEDED", ("tag_name",), ())
        if statement.startswith("CREATE GOVERNED TAG"):
            raise StatementError("already exists")
        if statement.startswith("DESCRIBE GOVERNED TAG"):
            value = (
                '["account_shared", "workspace_scoped"]'
                if "system_table_scope" in statement
                else "[]"
            )
            return StatementResult(
                "d", "SUCCEEDED", ("info_name", "info_value"), (("Allowed Values", value),)
            )
        if statement.startswith("SHOW EFFECTIVE"):
            return StatementResult(
                "p",
                "SUCCEEDED",
                ("policy_name", "policy_type"),
                (("workspace_scope", "ROW_FILTER"),),
            )
        return StatementResult("x", "SUCCEEDED")

    assert apply_plan(
        FakeClient(handler), plan, plan.digest, policy_attempts=1, policy_interval_seconds=0
    )


def test_statement_failure_stops_without_sensitive_detail() -> None:
    plan = sample_plan()

    def handler(statement: str, rows: bool) -> StatementResult:
        if (
            statement.startswith("SELECT current_user")
            or statement in {"SHOW GOVERNED TAGS"}
            or statement.startswith("DESCRIBE")
        ):
            return handler_factory()(statement, rows)
        raise StatementError("sensitive row")

    with pytest.raises(ApplyError) as captured:
        apply_plan(
            FakeClient(handler), plan, plan.digest, policy_attempts=1, policy_interval_seconds=0
        )
    assert "sensitive" not in str(captured.value)
