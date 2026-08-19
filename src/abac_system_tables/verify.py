"""Representative-principal verification through Statement Execution."""

from __future__ import annotations

from dataclasses import dataclass

from . import sql
from .apply import ApplyError, validate_identity
from .client import SqlClient, StatementError
from .config import Config, VerifyScenario


class VerificationError(RuntimeError):
    """A least-privilege expectation was violated."""


@dataclass(frozen=True, slots=True)
class CheckResult:
    relation: str
    expectation: str
    status: str
    observed_count: int | None = None


def _integer(value: str | None, field: str) -> int:
    try:
        result = int(value or "")
    except ValueError as exc:
        raise VerificationError(f"verification returned invalid {field}") from exc
    if result < 0:
        raise VerificationError(f"verification returned negative {field}")
    return result


def _verify_membership(
    client: SqlClient, scenario: VerifyScenario, config: Config, identity: str
) -> tuple[str, ...]:
    groups = {group.name: group.workspace_ids for group in config.consumer_groups}
    if scenario.consumer_group not in groups:
        raise VerificationError(f"scenario {scenario.name!r} names an unconfigured consumer group")
    if identity in config.trusted_principals:
        raise VerificationError(f"scenario {scenario.name!r} identity is a trusted exemption")
    result = client.execute(
        sql.verify_membership_sql(scenario.consumer_group, config.trusted_principals),
        include_rows=True,
    )
    expected_columns = (
        "consumer_member",
        *(f"trusted_member_{index}" for index in range(len(config.trusted_principals))),
    )
    if (
        result.columns != expected_columns
        or len(result.rows) != 1
        or len(result.rows[0]) != len(expected_columns)
    ):
        raise VerificationError("group-membership verification returned malformed evidence")
    values = tuple((value or "").casefold() for value in result.rows[0])
    if values[0] != "true":
        raise VerificationError(f"scenario {scenario.name!r} identity is not in its consumer group")
    if any(value != "false" for value in values[1:]):
        raise VerificationError(
            f"scenario {scenario.name!r} identity is in a trusted exemption group"
        )
    return groups[scenario.consumer_group]


def verify_scenario(
    client: SqlClient, scenario: VerifyScenario, config: Config
) -> tuple[CheckResult, ...]:
    try:
        identity = validate_identity(client)
    except ApplyError as exc:
        raise VerificationError(f"scenario {scenario.name!r} identity validation failed") from exc
    if identity != scenario.expected_identity:
        raise VerificationError(
            f"scenario {scenario.name!r} authenticated as an unexpected identity"
        )
    allowed = _verify_membership(client, scenario, config, identity)
    results: list[CheckResult] = []
    for check in scenario.checks:
        if check.expectation == "denied":
            try:
                client.execute(sql.verify_access_sql(check.relation), include_rows=False)
            except StatementError as exc:
                if exc.is_authorization_denied:
                    results.append(CheckResult(check.relation, check.expectation, "passed"))
                    continue
                raise VerificationError(
                    f"scenario {scenario.name!r}: denial lacked authorization evidence"
                ) from exc
            raise VerificationError(
                f"scenario {scenario.name!r}: denied relation was accessible: {check.relation}"
            )
        if check.expectation == "shared":
            try:
                client.execute(sql.verify_access_sql(check.relation), include_rows=False)
            except StatementError as exc:
                raise VerificationError(
                    f"scenario {scenario.name!r}: shared relation was not accessible: "
                    f"{check.relation}"
                ) from exc
            results.append(CheckResult(check.relation, check.expectation, "passed"))
            continue
        try:
            result = client.execute(
                sql.verify_scoped_sql(check.relation, allowed), include_rows=True
            )
        except StatementError as exc:
            raise VerificationError(
                f"scenario {scenario.name!r}: scoped relation query failed: {check.relation}"
            ) from exc
        if (
            result.columns != ("observed_count", "violation_count")
            or len(result.rows) != 1
            or len(result.rows[0]) != 2
        ):
            raise VerificationError(
                f"scenario {scenario.name!r}: unexpected scoped result schema for {check.relation}"
            )
        observed = _integer(result.rows[0][0], "observed count")
        violations = _integer(result.rows[0][1], "violation count")
        if violations:
            raise VerificationError(
                f"scenario {scenario.name!r}: {violations} disallowed row(s) were visible in "
                f"{check.relation}"
            )
        if observed == 0:
            raise VerificationError(
                f"scenario {scenario.name!r}: expected at least one permitted workspace scope"
            )
        results.append(CheckResult(check.relation, check.expectation, "passed", observed))
    return tuple(results)
