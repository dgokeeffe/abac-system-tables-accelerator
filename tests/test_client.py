from __future__ import annotations

from types import SimpleNamespace

import pytest

from abac_system_tables.client import DatabricksSqlClient, StatementError


def response(
    state: str,
    *,
    statement_id: str = "raw-statement-id",
    rows: list[list[object | None]] | None = None,
    truncated: bool = False,
    next_chunk_index: int | None = None,
    error_code: str | None = None,
    sql_state: str | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        statement_id=statement_id,
        status=SimpleNamespace(
            state=SimpleNamespace(value=state),
            error=SimpleNamespace(
                message="platform detail", error_code=error_code, sql_state=sql_state
            ),
        ),
        manifest=SimpleNamespace(
            schema=SimpleNamespace(columns=[SimpleNamespace(name="workspace_id")]),
            truncated=truncated,
            total_chunk_count=1,
        ),
        result=SimpleNamespace(
            data_array=rows or [], next_chunk_index=next_chunk_index, external_links=[]
        ),
    )


class FakeExecutionApi:
    def __init__(self, responses: list[SimpleNamespace]) -> None:
        self.responses = responses
        self.cancelled: list[str] = []

    def execute_statement(self, **_kwargs: object) -> SimpleNamespace:
        return self.responses.pop(0)

    def get_statement(self, **_kwargs: object) -> SimpleNamespace:
        return self.responses.pop(0)

    def cancel_execution(self, *, statement_id: str) -> None:
        self.cancelled.append(statement_id)


class FakeWorkspace:
    def __init__(self, api: FakeExecutionApi) -> None:
        self.statement_execution = api


def test_sdk_client_polls_and_returns_rows_only_when_requested() -> None:
    api = FakeExecutionApi([response("PENDING"), response("SUCCEEDED", rows=[["111"], [None]])])
    client = DatabricksSqlClient(
        "explicit-profile",
        "warehouse",
        poll_interval_seconds=0,
        workspace_client=FakeWorkspace(api),
    )
    result = client.execute("SELECT", include_rows=True)
    assert result.columns == ("workspace_id",)
    assert result.rows == (("111",), (None,))

    api = FakeExecutionApi([response("SUCCEEDED", rows=[["must-not-return"]])])
    client = DatabricksSqlClient("p", "w", workspace_client=FakeWorkspace(api))
    result = client.execute("ALTER", include_rows=False)
    assert result.rows == ()
    assert result.columns == ()


def test_sdk_client_refuses_truncated_evidence() -> None:
    api = FakeExecutionApi([response("SUCCEEDED", rows=[["111"]], truncated=True)])
    client = DatabricksSqlClient("p", "w", workspace_client=FakeWorkspace(api))
    with pytest.raises(StatementError, match="partial"):
        client.execute("SELECT", include_rows=True)

    api = FakeExecutionApi([response("SUCCEEDED", rows=[["111"]], next_chunk_index=1)])
    client = DatabricksSqlClient("p", "w", workspace_client=FakeWorkspace(api))
    with pytest.raises(StatementError, match="partial"):
        client.execute("SELECT", include_rows=True)


def test_sdk_client_fails_for_terminal_error() -> None:
    api = FakeExecutionApi([response("FAILED")])
    client = DatabricksSqlClient("p", "w", workspace_client=FakeWorkspace(api))
    with pytest.raises(StatementError, match="FAILED") as captured:
        client.execute("SELECT")
    assert captured.value.state == "FAILED"

    api = FakeExecutionApi([response("FAILED", error_code="PERMISSION_DENIED", sql_state="42501")])
    client = DatabricksSqlClient("p", "w", workspace_client=FakeWorkspace(api))
    with pytest.raises(StatementError) as denied:
        client.execute("SELECT")
    assert denied.value.is_authorization_denied


def test_sdk_client_requests_cancellation_on_timeout() -> None:
    api = FakeExecutionApi([response("PENDING")])
    client = DatabricksSqlClient(
        "p",
        "w",
        total_timeout_seconds=0,
        workspace_client=FakeWorkspace(api),
    )
    with pytest.raises(StatementError, match="timed out"):
        client.execute("SELECT")
    assert api.cancelled == ["raw-statement-id"]


@pytest.mark.parametrize(("profile", "warehouse"), [("", "warehouse"), ("profile", "")])
def test_sdk_client_requires_explicit_connection(profile: str, warehouse: str) -> None:
    with pytest.raises(ValueError):
        DatabricksSqlClient(
            profile, warehouse, workspace_client=FakeWorkspace(FakeExecutionApi([]))
        )
