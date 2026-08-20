from __future__ import annotations

import pytest

from abac_system_tables.client import StatementError, StatementResult
from abac_system_tables.config import VerifyCheck, VerifyScenario, loads_config
from abac_system_tables.verify import VerificationError, verify_scenario
from tests.helpers import FakeClient, valid_config_text

CONFIG = loads_config(valid_config_text())


def scenario(*checks: VerifyCheck) -> VerifyScenario:
    return VerifyScenario("representative", "sp-profile", "sp", "bu_alpha", checks)


def client(
    *,
    observed: int = 2,
    violations: int = 0,
    denied_error: StatementError | None = None,
    denied_table: str = "node_types",
    member: str = "true",
    trusted: str = "false",
) -> FakeClient:
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
                ((member, trusted, "false"),),
            )
        if "violation_count" in statement:
            return StatementResult(
                "q",
                "SUCCEEDED",
                ("observed_count", "violation_count"),
                ((str(observed), str(violations)),),
            )
        if denied_error and denied_table in statement:
            raise denied_error
        return StatementResult("a", "SUCCEEDED")

    return FakeClient(handler)


def test_direct_scoped_shared_and_denied_checks() -> None:
    checks = (
        VerifyCheck("system.access.audit", "scoped"),
        VerifyCheck("system.billing.list_prices", "shared"),
        VerifyCheck("system.compute.node_types", "denied"),
    )
    denied = StatementError("denied", error_code="PERMISSION_DENIED", sql_state="42501")
    results = verify_scenario(client(observed=1501, denied_error=denied), scenario(*checks), CONFIG)
    assert [result.status for result in results] == ["passed", "passed", "passed"]
    assert results[0].observed_count == 1501


@pytest.mark.parametrize(("observed", "violations"), [(0, 0), (1, 1)])
def test_scoped_requires_nonempty_and_zero_violations(observed: int, violations: int) -> None:
    with pytest.raises(VerificationError):
        verify_scenario(
            client(observed=observed, violations=violations),
            scenario(VerifyCheck("system.access.audit", "scoped")),
            CONFIG,
        )


@pytest.mark.parametrize(
    "error",
    [
        StatementError("timeout", state="TIMED_OUT"),
        StatementError("not found", error_code="TABLE_OR_VIEW_NOT_FOUND", sql_state="42P01"),
        StatementError("cancel", state="CANCELED"),
    ],
)
def test_denied_requires_authorization_specific_error(error: StatementError) -> None:
    with pytest.raises(VerificationError, match="authorization evidence"):
        verify_scenario(
            client(denied_error=error, denied_table="audit"),
            scenario(VerifyCheck("system.access.audit", "denied")),
            CONFIG,
        )


def test_membership_identity_and_trusted_exemption_are_proven() -> None:
    check = VerifyCheck("system.access.audit", "scoped")
    with pytest.raises(VerificationError, match="not in"):
        verify_scenario(client(member="false"), scenario(check), CONFIG)
    with pytest.raises(VerificationError, match="trusted"):
        verify_scenario(client(trusted="true"), scenario(check), CONFIG)
    wrong = VerifyScenario("r", "p", "other", "bu_alpha", (check,))
    with pytest.raises(VerificationError, match="unexpected identity"):
        verify_scenario(client(), wrong, CONFIG)
    unknown = VerifyScenario("r", "p", "sp", "missing", (check,))
    with pytest.raises(VerificationError, match="unconfigured"):
        verify_scenario(client(), unknown, CONFIG)


def test_denied_accessible_and_shared_denied_fail() -> None:
    with pytest.raises(VerificationError, match="was accessible"):
        verify_scenario(client(), scenario(VerifyCheck("system.access.audit", "denied")), CONFIG)
    denied = StatementError("denied", error_code="PERMISSION_DENIED")
    with pytest.raises(VerificationError, match="shared relation"):
        verify_scenario(
            client(denied_error=denied, denied_table="list_prices"),
            scenario(VerifyCheck("system.billing.list_prices", "shared")),
            CONFIG,
        )
