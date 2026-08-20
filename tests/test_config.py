from __future__ import annotations

import json

import pytest

from abac_system_tables.config import ConfigError, loads_config, loads_verify_config
from tests.helpers import valid_config_data, valid_config_text


def test_valid_v2_config_is_canonical_and_deterministic() -> None:
    first = loads_config(valid_config_text())
    second = loads_config(json.dumps(valid_config_data(), indent=4, sort_keys=True))
    assert first == second and first.version == 2
    assert first.digest == second.digest and len(first.digest) == 64
    assert first.governance.catalog == "governance_catalog"


def test_v1_is_rejected_with_migration_guidance() -> None:
    old = valid_config_data()
    old["version"] = 1
    old["facade"] = {"catalog": "old", "schema": "published", "refresh_every_hours": 24}
    old.pop("governance")
    with pytest.raises(ConfigError, match="migrate to v2 governance"):
        loads_config(json.dumps(old))


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (lambda data: data.update({"unknown": True}), "unknown field"),
        (lambda data: data["governance"].update({"catalog": "bad;drop"}), "identifier"),
        (lambda data: data["governance"].update({"catalog": "system"}), "tenant-owned"),
        (
            lambda data: data["governance"].update({"schema": "information_schema"}),
            "information_schema",
        ),
        (
            lambda data: data["consumer_groups"][0].update({"workspace_ids": ["abc"]}),
            "workspace ID",
        ),
        (lambda data: data["consumer_groups"][0].update({"name": "bad`group"}), "principal"),
        (lambda data: data.update({"trusted_principals": ["bu_alpha"]}), "overlap"),
        (
            lambda data: data["tags"].update({"workspace_column_key": "system_table_scope"}),
            "differ",
        ),
        (
            lambda data: data["consumer_groups"][0].update({"workspace_ids": ["111", "111"]}),
            "duplicates",
        ),
        (lambda data: data.update({"trusted_principals": []}), "at least one"),
        (lambda data: data.update({"trusted_principals": ["account users"]}), "must not exempt"),
    ],
)
def test_invalid_config_is_rejected(mutate: object, match: str) -> None:
    data = valid_config_data()
    assert callable(mutate)
    mutate(data)  # type: ignore[operator]
    with pytest.raises(ConfigError, match=match):
        loads_config(json.dumps(data))


def test_duplicate_json_key_and_policy_quota_are_rejected() -> None:
    with pytest.raises(ConfigError, match="duplicate JSON key"):
        loads_config(valid_config_text()[:-1] + ',"version":2}')
    data = valid_config_data()
    data["trusted_principals"] = [f"trusted_{index}" for index in range(20)]
    with pytest.raises(ConfigError, match="at most 19"):
        loads_config(json.dumps(data))


def test_workspace_overlap_is_explicit_union() -> None:
    data = valid_config_data()
    data["consumer_groups"][1]["workspace_ids"] = ["111", "333"]
    parsed = loads_config(json.dumps(data))
    assert parsed.consumer_groups[1].workspace_ids == ("111", "333")


def test_account_shared_requires_rationale_and_system_relation() -> None:
    data = valid_config_data()
    data["overrides"] = [{"source": "system.billing.list_prices", "disposition": "account_shared"}]
    with pytest.raises(ConfigError, match="mandatory"):
        loads_config(json.dumps(data))
    data["overrides"][0]["rationale"] = "This account reference is safe for every configured group."
    assert loads_config(json.dumps(data)).overrides[0].disposition == "account_shared"
    data["overrides"][0]["source"] = "other.billing.list_prices"
    with pytest.raises(ConfigError, match="system"):
        loads_config(json.dumps(data))


@pytest.mark.parametrize(
    "addition",
    [
        {"client_secret": "not-real"},
        {"comment": "dapi" + "1" * 30},
        {"comment": "-----BEGIN " + "PRIVATE KEY-----"},
        {"comment": "Bearer abcdefghijklmnopqrstuvwxyz"},
    ],
)
def test_secret_shapes_are_rejected(addition: dict[str, str]) -> None:
    data = valid_config_data()
    data.update(addition)
    with pytest.raises(ConfigError, match="secret-shaped"):
        loads_config(json.dumps(data))


def verify_data(relation: str = "system.access.audit") -> dict[str, object]:
    return {
        "version": 1,
        "scenarios": [
            {
                "name": "representative",
                "profile": "sp_profile",
                "expected_identity": "sp-application-identity",
                "consumer_group": "bu_alpha",
                "checks": [{"relation": relation, "expectation": "scoped"}],
            }
        ],
    }


def test_verify_config_requires_direct_system_relations() -> None:
    assert loads_verify_config(json.dumps(verify_data())).scenarios[0].consumer_group == "bu_alpha"
    with pytest.raises(ConfigError, match="direct system"):
        loads_verify_config(json.dumps(verify_data("facade.published.audit")))
    raw = verify_data()
    raw["scenarios"][0]["checks"][0]["extra"] = True  # type: ignore[index]
    with pytest.raises(ConfigError, match="unknown field"):
        loads_verify_config(json.dumps(raw))
