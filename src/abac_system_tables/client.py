"""Statement Execution API abstraction and Databricks SDK adapter."""

from __future__ import annotations

import time
from contextlib import suppress
from dataclasses import dataclass
from typing import Any, Protocol


class StatementError(RuntimeError):
    """A SQL statement failed, was cancelled, timed out, or returned partial evidence."""

    def __init__(
        self,
        message: str,
        *,
        state: str | None = None,
        error_code: str | None = None,
        sql_state: str | None = None,
    ) -> None:
        super().__init__(message)
        self.state = state
        self.error_code = error_code
        self.sql_state = sql_state

    @property
    def is_authorization_denied(self) -> bool:
        code = (self.error_code or "").upper()
        return self.sql_state == "42501" or code in {
            "PERMISSION_DENIED",
            "INSUFFICIENT_PERMISSIONS",
            "INSUFFICIENT_PRIVILEGES",
        }


@dataclass(frozen=True, slots=True)
class StatementResult:
    statement_id: str
    state: str
    columns: tuple[str, ...] = ()
    rows: tuple[tuple[str | None, ...], ...] = ()


class SqlClient(Protocol):
    def execute(self, statement: str, *, include_rows: bool = False) -> StatementResult: ...


class DatabricksSqlClient:
    """Synchronous, explicit-profile Statement Execution client."""

    def __init__(
        self,
        profile: str,
        warehouse_id: str,
        *,
        wait_timeout_seconds: int = 50,
        poll_interval_seconds: float = 0.5,
        total_timeout_seconds: int = 600,
        workspace_client: Any | None = None,
    ) -> None:
        if not profile.strip():
            raise ValueError("an explicit Databricks profile is required")
        if not warehouse_id.strip():
            raise ValueError("a SQL warehouse ID is required")
        if workspace_client is None:
            from databricks.sdk import WorkspaceClient

            workspace_client = WorkspaceClient(profile=profile)
        self._api = workspace_client.statement_execution
        self._warehouse_id = warehouse_id
        self._wait_timeout = wait_timeout_seconds
        self._poll_interval = poll_interval_seconds
        self._total_timeout = total_timeout_seconds

    @staticmethod
    def _state(response: Any) -> str:
        value = getattr(getattr(response, "status", None), "state", None)
        return str(getattr(value, "value", value or "UNKNOWN"))

    @staticmethod
    def _error(response: Any) -> tuple[str, str | None, str | None]:
        error = getattr(getattr(response, "status", None), "error", None)
        # Platform error messages can contain SQL text, object names, principals or IDs.
        # Preserve only structured classification fields; callers receive a fixed message.
        code = getattr(error, "error_code", None)
        sql_state = getattr(error, "sql_state", None)
        return (
            "statement failed",
            str(code) if code else None,
            str(sql_state) if sql_state else None,
        )

    @staticmethod
    def _result(response: Any, include_rows: bool) -> StatementResult:
        statement_id = str(getattr(response, "statement_id", "") or "")
        state = DatabricksSqlClient._state(response)
        if not include_rows:
            return StatementResult(statement_id, state)
        manifest = getattr(response, "manifest", None)
        result = getattr(response, "result", None)
        total_chunks = getattr(manifest, "total_chunk_count", None)
        continuation = getattr(result, "next_chunk_index", None)
        external_links = getattr(result, "external_links", None)
        if (
            bool(getattr(manifest, "truncated", False))
            or (total_chunks is not None and int(total_chunks) > 1)
            or continuation is not None
            or bool(external_links)
        ):
            raise StatementError("statement result was partial; refusing incomplete evidence")
        schema = getattr(manifest, "schema", None)
        columns = tuple(
            str(getattr(item, "name", "")) for item in getattr(schema, "columns", []) or []
        )
        data = getattr(result, "data_array", None) or []
        rows = tuple(tuple(None if cell is None else str(cell) for cell in row) for row in data)
        return StatementResult(statement_id, state, columns, rows)

    def execute(self, statement: str, *, include_rows: bool = False) -> StatementResult:
        response = self._api.execute_statement(
            warehouse_id=self._warehouse_id,
            statement=statement,
            wait_timeout=f"{self._wait_timeout}s",
        )
        deadline = time.monotonic() + self._total_timeout
        state = self._state(response)
        while state in {"PENDING", "RUNNING"}:
            if time.monotonic() >= deadline:
                statement_id = str(getattr(response, "statement_id", "") or "")
                with suppress(Exception):
                    self._api.cancel_execution(statement_id=statement_id)
                raise StatementError("statement timed out", state="TIMED_OUT")
            time.sleep(self._poll_interval)
            response = self._api.get_statement(statement_id=str(response.statement_id))
            state = self._state(response)
        if state != "SUCCEEDED":
            message, code, sql_state = self._error(response)
            raise StatementError(
                f"statement ended in {state}: {message}",
                state=state,
                error_code=code,
                sql_state=sql_state,
            )
        return self._result(response, include_rows)
