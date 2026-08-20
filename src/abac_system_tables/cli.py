"""Command-line interface for planning, applying, and verifying the accelerator."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from .apply import apply_plan
from .client import DatabricksSqlClient, SqlClient
from .config import Config, ConfigError, load_config, loads_verify_config
from .plan import Plan, build_plan, discover, discover_governance_state
from .verify import verify_scenario

ClientFactory = Callable[[str, str], SqlClient]


def _warehouse_id(value: str | None) -> str:
    warehouse_id = value or os.environ.get("DATABRICKS_WAREHOUSE_ID", "")
    if not warehouse_id.strip():
        raise ConfigError(
            "provide --warehouse-id or set DATABRICKS_WAREHOUSE_ID outside the repository"
        )
    return warehouse_id


def _client(profile: str, warehouse_id: str) -> SqlClient:
    return DatabricksSqlClient(profile, warehouse_id)


def _write(payload: object, output: Path | None) -> None:
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if output is None:
        sys.stdout.write(text)
    else:
        output.write_text(text, encoding="utf-8")


def _load_plan(args: argparse.Namespace, factory: ClientFactory) -> tuple[Config, Plan, SqlClient]:
    config = load_config(args.config)
    warehouse_id = _warehouse_id(args.warehouse_id)
    client = factory(args.profile, warehouse_id)
    sources = discover(client)
    governance_state = discover_governance_state(client, config)
    plan = build_plan(config, sources, governance_state)
    return config, plan, client


def _plan_command(args: argparse.Namespace, factory: ClientFactory) -> int:
    _config, plan, _client_instance = _load_plan(args, factory)
    _write(plan.redacted(), args.output)
    return 0


def _apply_command(args: argparse.Namespace, factory: ClientFactory) -> int:
    _config, plan, client = _load_plan(args, factory)
    applied = apply_plan(client, plan, args.confirm)
    _write(
        {
            "configDigest": plan.config_digest,
            "planDigest": plan.digest,
            "steps": [
                {
                    "order": item.order,
                    "kind": item.kind,
                    "statementRef": item.statement_ref,
                    "state": item.state,
                }
                for item in applied
            ],
        },
        args.output,
    )
    return 0


def _verify_command(args: argparse.Namespace, factory: ClientFactory) -> int:
    config = load_config(args.config)
    verify_config = loads_verify_config(args.scenarios.read_text(encoding="utf-8"))
    warehouse_id = _warehouse_id(args.warehouse_id)
    summaries: list[dict[str, object]] = []
    for scenario in verify_config.scenarios:
        client = factory(scenario.profile, warehouse_id)
        results = verify_scenario(client, scenario, config)
        summaries.append(
            {
                "scenarioRef": "sha256:" + hashlib.sha256(scenario.name.encode()).hexdigest()[:12],
                "checks": [
                    {
                        "relationRef": "sha256:"
                        + hashlib.sha256(item.relation.encode()).hexdigest()[:12],
                        "expectation": item.expectation,
                        "status": item.status,
                        **(
                            {"observedWorkspaceScopeCount": item.observed_count}
                            if item.observed_count is not None
                            else {}
                        ),
                    }
                    for item in results
                ],
            }
        )
    _write({"scenarios": summaries}, args.output)
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="abac-system-tables",
        description="Plan, apply, and verify direct ABAC on Databricks system tables.",
    )
    subparsers = root.add_subparsers(dest="command", required=True)

    def connection(command: argparse.ArgumentParser) -> None:
        command.add_argument("--profile", required=True, help="Explicit administrator profile")
        command.add_argument(
            "--warehouse-id",
            help="SQL warehouse ID; prefer DATABRICKS_WAREHOUSE_ID to avoid shell history",
        )
        command.add_argument("--output", type=Path, help="Write redacted JSON output")

    plan_parser = subparsers.add_parser("plan", help="Discover and emit a mutation-free plan")
    plan_parser.add_argument("--config", type=Path, required=True)
    connection(plan_parser)

    apply_parser = subparsers.add_parser("apply", help="Apply an exact reviewed plan digest")
    apply_parser.add_argument("--config", type=Path, required=True)
    apply_parser.add_argument("--confirm", required=True, help="Exact planDigest from plan")
    connection(apply_parser)

    verify_parser = subparsers.add_parser(
        "verify", help="Test scenarios using profiles that authenticate as each principal"
    )
    verify_parser.add_argument("--config", type=Path, required=True)
    verify_parser.add_argument("--scenarios", type=Path, required=True)
    verify_parser.add_argument(
        "--warehouse-id",
        help="SQL warehouse ID; prefer DATABRICKS_WAREHOUSE_ID to avoid shell history",
    )
    verify_parser.add_argument("--output", type=Path, help="Write row-data-free JSON output")
    return root


def main(
    argv: Sequence[str] | None = None,
    *,
    client_factory: ClientFactory = _client,
) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "plan":
            return _plan_command(args, client_factory)
        if args.command == "apply":
            return _apply_command(args, client_factory)
        return _verify_command(args, client_factory)
    except ConfigError:
        # Validation errors can contain configured principals or live object names.
        print(
            "configuration or discovered state is invalid; no tenant metadata was emitted",
            file=sys.stderr,
        )
    except Exception:
        # Platform errors can contain tenant metadata. Keep normal console output generic;
        # administrators can use SDK debug logging only in a protected local environment.
        print("operation failed; no tenant row data was emitted", file=sys.stderr)
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
