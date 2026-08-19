from __future__ import annotations

import json

import pytest

from abac_system_tables.config import ConfigError, loads_config, loads_verify_config
from tests.helpers import valid_config_data, valid_config_text


def test_valid_config_is_canonical_and_deterministic() -> None:
    first = loads_config(valid_config_text())
    second = loads_config(json.dumps(valid_config_data(), indent=4, sort_keys=True))
    assert first == second
    assert first.digest == second.digest
    assert len(first.digest) == 64


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (lambda data: data.update({"unknown": True}), "unknown field"),
        (lambda data: data["facade"].update({"catalog": "bad;drop"}), "identifier"),
        (lambda data: data["facade"].update({"catalog": "system"}), "non-reserved"),
        (
            lambda data: data["facade"].update({"schema": "information_schema"}),
            "reserved information_schema",
        ),
        (
            lambda data: data["consumer_groups"][0].update({"workspace_ids": ["abc"]}),
            "workspace ID",
        ),
        (lambda data: data["consumer_groups"][0].update({"name": "bad`group"}), "principal"),
        (lambda data: data.update({"trusted_principals": ["bu_alpha"]}), "overlap"),
        (
            lambda data: data["tags"].update({"workspace_column_key": "system_table_scope"}),
            "must differ",
        ),
        (
            lambda data: data["consumer_groups"][0].update({"workspace_ids": ["111", "111"]}),
            "duplicates",
        ),
        (lambda data: data.update({"trusted_principals": []}), "at least one"),
        (
            lambda data: data.update({"trusted_principals": ["account users"]}),
            "must not exempt",
        ),
    ],
)
def test_invalid_config_is_rejected(mutate: object, match: str) -> None:
    data = valid_config_data()
    assert callable(mutate)
    mutate(data)  # type: ignore[operator]
    with pytest.raises(ConfigError, match=match):
        loads_config(json.dumps(data))


def test_duplicate_json_key_is_rejected() -> None:
    with pytest.raises(ConfigError, match="duplicate JSON key"):
        loads_config(valid_config_text()[:-1] + ',"version":1}')


def test_policy_principal_quota_is_enforced_only_for_exemptions() -> None:
    data = valid_config_data()
    data["consumer_groups"] = [
        {"name": f"group_{index}", "workspace_ids": [str(index + 1)]} for index in range(25)
    ]
    assert len(loads_config(json.dumps(data)).consumer_groups) == 25
    data["trusted_principals"] = [f"trusted_{index}" for index in range(20)]
    with pytest.raises(ConfigError, match="at most 19"):
        loads_config(json.dumps(data))


def test_workspace_assignment_overlap_across_groups_is_an_explicit_union() -> None:
    data = valid_config_data()
    data["consumer_groups"][1]["workspace_ids"] = ["111", "333"]
    parsed = loads_config(json.dumps(data))
    assert parsed.consumer_groups[0].workspace_ids == ("111", "222")
    assert parsed.consumer_groups[1].workspace_ids == ("111", "333")


def test_account_shared_requires_substantive_rationale() -> None:
    data = valid_config_data()
    data["overrides"] = [{"source": "system.billing.list_prices", "disposition": "account_shared"}]
    with pytest.raises(ConfigError, match="mandatory"):
        loads_config(json.dumps(data))
    data["overrides"][0]["rationale"] = "short"
    with pytest.raises(ConfigError, match="at least 20"):
        loads_config(json.dumps(data))
    data["overrides"][0]["rationale"] = "This account reference is safe for every configured group."
    assert loads_config(json.dumps(data)).overrides[0].disposition == "account_shared"


@pytest.mark.parametrize(
    "addition",
    [
        {"client_secret": "not-even-a-real-value"},
        {"comment": "dapi" + "1" * 30},
        {"comment": "-----BEGIN " + "PRIVATE KEY-----"},
        {"comment": "Bearer abcdefghijklmnopqrstuvwxyz"},
    ],
)
def test_secret_shaped_keys_and_values_are_rejected(addition: dict[str, str]) -> None:
    data = valid_config_data()
    data.update(addition)
    with pytest.raises(ConfigError, match="secret-shaped"):
        loads_config(json.dumps(data))


def test_override_source_and_duplicate_are_rejected() -> None:
    data = valid_config_data()
    override = {"source": "other.schema.table", "disposition": "admin_only"}
    data["overrides"] = [override]
    with pytest.raises(ConfigError, match="system"):
        loads_config(json.dumps(data))
    override["source"] = "system.access.audit"
    data["overrides"] = [override, dict(override)]
    with pytest.raises(ConfigError, match="duplicates"):
        loads_config(json.dumps(data))


def test_verify_config_is_strict() -> None:
    raw = {
        "version": 1,
        "scenarios": [
            {
                "name": "representative",
                "profile": "sp_profile",
                "expected_identity": "sp-application-identity",
                "consumer_group": "bu_alpha",
                "checks": [
                    {
                        "relation": "facade.published.access__audit",
                        "expectation": "scoped",
                    },
                    {"relation": "system.access.audit", "expectation": "denied"},
                ],
            }
        ],
    }
    parsed = loads_verify_config(json.dumps(raw))
    assert parsed.scenarios[0].consumer_group == "bu_alpha"
    raw["version"] = True
    with pytest.raises(ConfigError, match="must equal 1"):
        loads_verify_config(json.dumps(raw))
    raw["version"] = 1
    raw["scenarios"][0]["checks"][0]["extra"] = True
    with pytest.raises(ConfigError, match="unknown field"):
        loads_verify_config(json.dumps(raw))


def test_verify_scoped_requires_allowed_ids_and_safe_relation() -> None:
    raw = {
        "version": 1,
        "scenarios": [
            {
                "name": "representative",
                "profile": "sp_profile",
                "expected_identity": "sp-application-identity",
                "consumer_group": "bu_alpha",
                "checks": [{"relation": "facade.published.audit", "expectation": "scoped"}],
            }
        ],
    }
    assert loads_verify_config(json.dumps(raw)).scenarios[0].checks[0].expectation == "scoped"
    raw["scenarios"][0]["checks"][0] = {
        "relation": "facade.published.audit;drop",
        "expectation": "denied",
    }
    with pytest.raises(ConfigError, match="safe three-part"):
        loads_verify_config(json.dumps(raw))
