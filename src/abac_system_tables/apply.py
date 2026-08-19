"""Confirmed, ordered application of an accelerator plan."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass

from . import sql
from .client import SqlClient, StatementError, StatementResult
from .plan import Plan, PlanStep


class ApplyError(RuntimeError):
    """The plan cannot be applied safely."""


@dataclass(frozen=True, slots=True)
class AppliedStep:
    order: int
    kind: str
    target: str
    statement_ref: str
    state: str


def _statement_ref(statement_id: str) -> str:
    if not statement_id:
        return "unavailable"
    return "sha256:" + hashlib.sha256(statement_id.encode()).hexdigest()[:12]


def validate_identity(client: SqlClient) -> str:
    result = client.execute(sql.identity_sql(), include_rows=True)
    if result.columns != ("current_identity", "session_identity") or len(result.rows) != 1:
        raise ApplyError("could not validate the current and session identities")
    current, session = result.rows[0]
    if not current or not session or current != session:
        raise ApplyError("current identity is empty or differs from the session identity")
    return current


def _parse_allowed_values(result: StatementResult) -> tuple[str, ...]:
    if result.columns != ("info_name", "info_value"):
        raise ApplyError("governed tag description returned an unexpected schema")
    rows = [row for row in result.rows if len(row) == 2 and row[0] is not None]
    matching: list[str] = []
    for name, value in rows:
        assert name is not None
        if name.strip().casefold() in {"allowed values", "values"}:
            matching.append(value or "")
    if len(matching) != 1:
        raise ApplyError("governed tag description did not contain one exact allowed-values field")
    raw = matching[0].strip()
    if not raw or raw in {"[]", "()"}:
        return ()
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = [part.strip().strip("'\"") for part in raw.strip("[]()").split(",")]
    if not isinstance(parsed, list) or any(
        not isinstance(value, str) or not value for value in parsed
    ):
        raise ApplyError("governed tag allowed-values field was malformed")
    if len(parsed) != len(set(parsed)):
        raise ApplyError("governed tag allowed-values field contained duplicates")
    return tuple(sorted(parsed))


def _tag_exists(client: SqlClient, step: PlanStep) -> bool:
    if step.tag_key is None:
        raise ApplyError("governed tag plan step is missing its tag key")
    result = client.execute(sql.show_governed_tags(), include_rows=True)
    candidates = [
        index
        for index, name in enumerate(result.columns)
        if name.strip().casefold().replace("_", "").replace(" ", "")
        in {"tagname", "tagkey", "name"}
    ]
    if len(candidates) != 1 or any(len(row) != len(result.columns) for row in result.rows):
        raise ApplyError("governed tag listing returned an unexpected schema")
    tag_index = candidates[0]
    exists = any(row[tag_index] == step.tag_key for row in result.rows)
    if not exists:
        return False
    description = client.execute(sql.describe_governed_tag(step.tag_key), include_rows=True)
    observed = _parse_allowed_values(description)
    expected = tuple(sorted(step.tag_values))
    if observed != expected:
        raise ApplyError(
            f"existing governed tag {step.tag_key!r} has an incompatible allowed-value set"
        )
    return True


def _execute_tag_step(client: SqlClient, step: PlanStep) -> AppliedStep:
    if step.tag_key is None:
        raise ApplyError("governed tag plan step is missing its tag key")
    if _tag_exists(client, step):
        return AppliedStep(step.order, step.kind, step.target, "pre-existing", "SUCCEEDED")
    try:
        result = client.execute(step.statement, include_rows=False)
    except StatementError:
        try:
            description = client.execute(sql.describe_governed_tag(step.tag_key), include_rows=True)
            if _parse_allowed_values(description) != tuple(sorted(step.tag_values)):
                raise ApplyError("concurrent governed tag is incompatible")
        except (StatementError, ApplyError) as proof_error:
            raise ApplyError(f"could not ensure governed tag {step.tag_key!r}") from proof_error
        return AppliedStep(step.order, step.kind, step.target, "concurrent-create", "SUCCEEDED")
    return AppliedStep(
        step.order, step.kind, step.target, _statement_ref(result.statement_id), result.state
    )


def _policy_effective(result: StatementResult) -> bool:
    names = {
        name.casefold().replace("_", "").replace(" ", ""): index
        for index, name in enumerate(result.columns)
    }
    if "policyname" not in names or "policytype" not in names:
        raise ApplyError("effective-policy check returned an unexpected schema")
    name_index, type_index = names["policyname"], names["policytype"]
    if any(len(row) != len(result.columns) for row in result.rows):
        raise ApplyError("effective-policy check returned malformed rows")
    row_filters = [
        row[name_index]
        for row in result.rows
        if (row[type_index] or "").replace(" ", "_").upper() == "ROW_FILTER"
    ]
    return row_filters == ["workspace_scope"]


def _execute_policy_gate(
    client: SqlClient,
    step: PlanStep,
    *,
    attempts: int,
    interval_seconds: float,
) -> AppliedStep:
    if attempts < 1:
        raise ApplyError("effective-policy attempts must be positive")
    last: StatementResult | None = None
    for attempt in range(attempts):
        try:
            last = client.execute(step.statement, include_rows=True)
        except StatementError as exc:
            raise ApplyError(f"effective policy could not be proven for {step.target}") from exc
        if _policy_effective(last):
            return AppliedStep(
                step.order, step.kind, step.target, _statement_ref(last.statement_id), "SUCCEEDED"
            )
        if attempt + 1 < attempts:
            time.sleep(interval_seconds)
    raise ApplyError(f"effective policy did not propagate for {step.target}; facade remains closed")


def apply_plan(
    client: SqlClient,
    plan: Plan,
    confirmation: str,
    *,
    policy_attempts: int = 30,
    policy_interval_seconds: float = 10.0,
) -> tuple[AppliedStep, ...]:
    """Apply the exact reviewed plan digest, returning row-data-free evidence."""
    if confirmation != plan.digest:
        raise ApplyError(
            "confirmation does not match the reviewed plan digest; run plan again and pass "
            "--confirm <planDigest>"
        )
    validate_identity(client)
    applied: list[AppliedStep] = []
    for step in plan.steps:
        if step.kind == "ensure_governed_tag":
            applied.append(_execute_tag_step(client, step))
            continue
        if step.kind == "verify_effective_policy":
            applied.append(
                _execute_policy_gate(
                    client,
                    step,
                    attempts=policy_attempts,
                    interval_seconds=policy_interval_seconds,
                )
            )
            continue
        try:
            result = client.execute(step.statement, include_rows=False)
        except StatementError as exc:
            raise ApplyError(f"step {step.order} ({step.kind}) failed for {step.target}") from exc
        applied.append(
            AppliedStep(
                step.order,
                step.kind,
                step.target,
                _statement_ref(result.statement_id),
                result.state,
            )
        )
    return tuple(applied)
