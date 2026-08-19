from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from abac_system_tables.client import StatementResult


def valid_config_data() -> dict[str, Any]:
    return {
        "version": 1,
        "facade": {
            "catalog": "facade_catalog",
            "schema": "published",
            "refresh_every_hours": 24,
        },
        "tags": {
            "table_key": "system_table_scope",
            "workspace_column_key": "workspace_scope_column",
        },
        "consumer_groups": [
            {"name": "bu_alpha", "workspace_ids": ["111", "222"]},
            {"name": "bu_beta", "workspace_ids": ["333"]},
        ],
        "trusted_principals": ["facade_admins", "facade_pipeline"],
        "overrides": [],
    }


def valid_config_text() -> str:
    return json.dumps(valid_config_data())


class FakeClient:
    def __init__(self, handler: Callable[[str, bool], StatementResult]) -> None:
        self.handler = handler
        self.calls: list[tuple[str, bool]] = []

    def execute(self, statement: str, *, include_rows: bool = False) -> StatementResult:
        self.calls.append((statement, include_rows))
        return self.handler(statement, include_rows)
