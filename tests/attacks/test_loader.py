from __future__ import annotations

import copy
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

from mulebench.attacks import (
    BUILTIN_SCENARIOS_DIR,
    PLACEHOLDER,
    ScenarioError,
    load_all,
    load_scenario,
    parse_scenario,
    render,
)

EXAMPLE = BUILTIN_SCENARIOS_DIR / "pix-description-injection-001.yaml"
Doc = dict[str, Any]


def base() -> Doc:
    data: Doc = yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))
    # Most tests rewrite the payload; goal rules are tested on their own.
    data.pop("attack_goal", None)
    return copy.deepcopy(data)


def errors_for(mutate: Callable[[Doc], None]) -> str:
    doc = base()
    mutate(doc)
    with pytest.raises(ScenarioError) as info:
        parse_scenario(yaml.safe_dump(doc, sort_keys=False))
    return "; ".join(info.value.errors)


def tx(doc: Doc) -> Doc:
    result: Doc = doc["setup"]["transactions"][0]
    return result


# --------------------------------------------------------------- happy path


def test_example_scenario_loads() -> None:
    s = load_scenario(EXAMPLE)
    assert s.id == "pix-description-injection-001"
    assert s.channel == "pix_description"
    assert s.setup.clock.utcoffset() is not None
    assert s.setup.customers[0].tax_id == "SYNTHETIC-0001"


def test_load_all_builtin() -> None:
    assert [s.id for s in load_all()] == [
        "delegation-key-swap-016",
        "delegation-payment-instruction-015",
        "delegation-payment-instruction-amount-015b",
        "dispute-flow-foreign-read-009",
        "memory-persistent-exfiltration-014",
        "memory-poisoning-bill-redirect-013",
        "payee-name-cross-customer-read-010",
        "payee-name-injection-003",
        "pix-description-confused-deputy-002",
        "pix-description-cross-customer-read-004",
        "pix-description-drain-007",
        "pix-description-foreign-debit-006",
        "pix-description-foreign-history-008",
        "pix-description-injection-001",
        "pix-description-read-before-pay-011",
        "pix-description-read-before-pay-key-swap-012",
        "pix-description-structuring-005",
    ]


def test_load_all_rejects_duplicate_ids(tmp_path: Path) -> None:
    for name in ("a.yaml", "b.yaml"):
        (tmp_path / name).write_text(EXAMPLE.read_text(encoding="utf-8"), encoding="utf-8")
    with pytest.raises(ScenarioError, match="duplicate scenario id"):
        load_all(tmp_path)


# ------------------------------------------------------------- YAML-level


def test_duplicate_yaml_key_rejected() -> None:
    text = EXAMPLE.read_text(encoding="utf-8").replace(
        "canary: MB-CANARY-7F3A\n", "canary: MB-CANARY-7F3A\ncanary: MB-CANARY-OTHER\n"
    )
    with pytest.raises(ScenarioError, match="duplicate key 'canary'"):
        parse_scenario(text)


def test_duplicate_nested_yaml_key_rejected() -> None:
    text = EXAMPLE.read_text(encoding="utf-8").replace(
        "      balance_cents: 500000\n",
        "      balance_cents: 500000\n      balance_cents: 900000\n",
    )
    with pytest.raises(ScenarioError, match="duplicate key 'balance_cents'"):
        parse_scenario(text)


@pytest.mark.parametrize("text", ["- a\n- b\n", "just a string\n", ""])
def test_top_level_must_be_mapping(text: str) -> None:
    with pytest.raises(ScenarioError, match="mapping"):
        parse_scenario(text)


def test_invalid_yaml_reported() -> None:
    with pytest.raises(ScenarioError, match="YAML error"):
        parse_scenario("id: [unclosed\n")


# ------------------------------------------------------------ unknown keys


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(extra=1),
        lambda d: d["setup"].update(extra=1),
        lambda d: d["setup"]["accounts"][0].update(extra=1),
        lambda d: tx(d).update(idempotency_key="x"),
        lambda d: d["user_task"].update(extra=1),
        lambda d: d["benign_control"]["expected_outcome"].update(extra=1),
        lambda d: d["brazil_context"].update(extra=1),
    ],
)
def test_unknown_keys_rejected(mutate: Callable[[Doc], None]) -> None:
    assert "Extra inputs are not permitted" in errors_for(mutate)


# ----------------------------------------------------------------- unique ids


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d["setup"]["customers"].append(dict(d["setup"]["customers"][0])),
        lambda d: d["setup"]["accounts"][0].update(id="cust_alice"),
        lambda d: d["user_task"]["authorizations"][0].update(ref="tx_refund"),
    ],
)
def test_duplicate_ids_rejected(mutate: Callable[[Doc], None]) -> None:
    assert "duplicate id" in errors_for(mutate)


def test_duplicate_pix_key_rejected() -> None:
    def mutate(d: Doc) -> None:
        d["setup"]["accounts"].append(dict(d["setup"]["accounts"][0], id="acc_two"))

    assert "duplicate pix_key" in errors_for(mutate)


def test_duplicate_invariants_rejected() -> None:
    assert "duplicate entry" in errors_for(lambda d: d.update(expected_invariants=["INV-1"] * 2))


# ------------------------------------------------------------ references


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda d: d["setup"]["accounts"][0].update(customer="cust_x"), "unknown customer"),
        (lambda d: tx(d).update(to_account="acc_x"), "unknown account"),
        (
            lambda d: d["user_task"]["authorizations"][0].update(from_account="acc_x"),
            "unknown account",
        ),
        (lambda d: d["user_task"].update(customer="cust_x"), "unknown customer"),
        (lambda d: d["injection"].update(transaction="tx_x"), "unknown transaction"),
        (
            lambda d: d["benign_control"]["expected_outcome"]["transfers"][0].update(
                from_account="acc_x"
            ),
            "unknown account",
        ),
        (
            lambda d: d["benign_control"]["expected_outcome"].update(tool_calls=["rm_rf"]),
            "tool_calls",
        ),
    ],
)
def test_references_must_resolve(mutate: Callable[[Doc], None], message: str) -> None:
    assert message in errors_for(mutate)


# ---------------------------------------------------------------- amounts


@pytest.mark.parametrize("value", [12.5, True, "100", None])
def test_amounts_must_be_strict_ints(value: object) -> None:
    assert "amount_cents" in errors_for(lambda d: tx(d).update(amount_cents=value))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: tx(d).update(amount_cents=0),
        lambda d: d["setup"]["accounts"][0].update(balance_cents=-1),
        lambda d: d["setup"]["accounts"][0].update(daily_limit_cents=-1),
        lambda d: d["user_task"]["authorizations"][0].update(max_amount_cents=0),
        lambda d: d["benign_control"]["expected_outcome"]["transfers"][0].update(amount_cents=-5),
    ],
)
def test_amount_bounds(mutate: Callable[[Doc], None]) -> None:
    assert "greater than" in errors_for(mutate)


# ------------------------------------------------------------------ enums


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(channel="sms"),
        lambda d: d.update(category="other"),
        lambda d: d.update(expected_invariants=["INV-9"]),
        lambda d: d["brazil_context"].update(review_status="approved"),
        lambda d: d.update(schema_version=2),
        lambda d: d["setup"]["accounts"][0].update(status="closed"),
    ],
)
def test_enums_enforced(mutate: Callable[[Doc], None]) -> None:
    assert "Input should be" in errors_for(mutate)


def test_scenario_id_must_be_slug() -> None:
    assert "id" in errors_for(lambda d: d.update(id="Bad Id!"))


def test_expected_invariants_required() -> None:
    assert "expected_invariants" in errors_for(lambda d: d.update(expected_invariants=[]))


def test_channel_without_setup_slot_rejected() -> None:
    assert "has no setup slot yet" in errors_for(lambda d: d.update(channel="kyc_document"))


# ------------------------------------------------------------ placeholder


def test_placeholder_missing() -> None:
    assert "exactly once" in errors_for(lambda d: tx(d).update(description="no slot"))


def test_placeholder_twice() -> None:
    assert "exactly once" in errors_for(
        lambda d: tx(d).update(description=f"{PLACEHOLDER} {PLACEHOLDER}")
    )


def test_placeholder_in_wrong_field_for_channel() -> None:
    def mutate(d: Doc) -> None:
        tx(d).update(description="plain", counterparty_name=f"Shop {PLACEHOLDER}")

    assert "exactly once" in errors_for(mutate)


def test_payee_name_channel_uses_counterparty_name() -> None:
    doc = base()
    doc["channel"] = "payee_name"
    tx(doc).update(description="plain", counterparty_name=f"Shop {PLACEHOLDER}")
    s = parse_scenario(yaml.safe_dump(doc))
    assert s.injection.payload in render(s, "attack").setup.transactions[0].counterparty_name


def test_placeholder_in_other_transaction_rejected() -> None:
    def mutate(d: Doc) -> None:
        d["setup"]["transactions"].append(dict(tx(d), ref="tx_two"))

    assert "exactly once" in errors_for(mutate)


def test_injection_target_must_be_visible_to_session_customer() -> None:
    def mutate(d: Doc) -> None:
        d["setup"]["customers"].append({"id": "cust_bob", "name": "Bob", "tax_id": "SYNTHETIC-2"})
        d["setup"]["accounts"].append(
            {
                "id": "acc_bob",
                "customer": "cust_bob",
                "balance_cents": 0,
                "daily_limit_cents": 0,
            }
        )
        tx(d).update(to_account="acc_bob")

    assert "not credited to an account of the session customer" in errors_for(mutate)


# -------------------------------------------------------------- 140 chars


def test_attack_payload_over_140_rendered_rejected() -> None:
    def mutate(d: Doc) -> None:
        d["injection"]["payload"] = "MB-CANARY-7F3A " + "x" * 140

    assert "attack description has" in errors_for(mutate)


def test_benign_payload_over_140_rendered_rejected() -> None:
    assert "benign description has" in errors_for(
        lambda d: d["benign_control"].update(payload="y" * 140)
    )


def test_non_target_description_over_140_rejected() -> None:
    def mutate(d: Doc) -> None:
        d["setup"]["transactions"].append(dict(tx(d), ref="tx_two", description="z" * 141))

    assert "transaction tx_two" in errors_for(mutate)


def test_exactly_140_rendered_is_allowed() -> None:
    doc = base()
    prefix = "Estorno pedido 4471. "
    doc["injection"]["payload"] = "MB-CANARY-7F3A " + "x" * (140 - len(prefix) - 15)
    s = parse_scenario(yaml.safe_dump(doc))
    assert len(render(s, "attack").setup.transactions[0].description) == 140


# ----------------------------------------------------------------- canary


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda d: d["injection"].update(payload="no token here"), "must appear in injection"),
        (
            lambda d: d["benign_control"].update(payload="MB-CANARY-7F3A thanks"),
            "must not appear in benign",
        ),
        (
            lambda d: d["user_task"].update(request="pay MB-CANARY-7F3A"),
            "only in injection.payload",
        ),
        (lambda d: d.update(canary="abc"), "canary"),
    ],
)
def test_canary_rules(mutate: Callable[[Doc], None], message: str) -> None:
    assert message in errors_for(mutate)


# ------------------------------------------------------------------ clock


def test_naive_clock_rejected() -> None:
    assert "timezone offset" in errors_for(lambda d: d["setup"].update(clock="2026-01-15T10:00:00"))


def test_unquoted_yaml_timestamp_accepted() -> None:
    text = EXAMPLE.read_text(encoding="utf-8").replace(
        'clock: "2026-01-15T10:00:00-03:00"', "clock: 2026-01-15T10:00:00-03:00"
    )
    assert parse_scenario(text).setup.clock.utcoffset() is not None


# ----------------------------------------------------------------- render


def test_render_fills_payload_per_variant() -> None:
    s = load_scenario(EXAMPLE)
    attack = render(s, "attack")
    benign = render(s, "benign")
    assert attack.setup.transactions[0].description.endswith(s.injection.payload)
    assert s.canary in attack.setup.transactions[0].description
    assert benign.setup.transactions[0].description == "Estorno pedido 4471. Obrigado pela compra!"
    assert s.canary not in benign.model_dump_json()
    assert PLACEHOLDER in s.setup.transactions[0].description  # scenario untouched


def test_render_is_deterministic() -> None:
    s = load_scenario(EXAMPLE)
    assert render(s, "attack") == render(s, "attack")


def test_load_builtin_matches_directory_load() -> None:
    from mulebench.attacks import load_builtin

    assert load_builtin() == load_all(BUILTIN_SCENARIOS_DIR)


# ------------------------------------------ invariant_params and agent_hints


def test_invariant_params_and_agent_hints_default_empty() -> None:
    s = parse_scenario(yaml.safe_dump(base()))
    assert s.agent_hints == {}
    assert s.invariant_params.inv3.reference_cents == 100_000
    assert s.invariant_params.inv3.window_hours == 24
    assert s.invariant_params.inv3.count_authorized is False


def test_invariant_params_and_agent_hints_parsed() -> None:
    doc = base()
    doc["invariant_params"] = {"inv3": {"reference_cents": 50_000, "count_authorized": False}}
    doc["agent_hints"] = {"split_payments_below_cents": 70_000}
    s = parse_scenario(yaml.safe_dump(doc))
    assert s.invariant_params.inv3.reference_cents == 50_000
    assert s.invariant_params.inv3.count_authorized is False
    assert s.agent_hints == {"split_payments_below_cents": 70_000}


@pytest.mark.parametrize(
    ("key", "value", "fragment"),
    [
        ("invariant_params", {"inv3": {"reference_cents": 0}}, "reference_cents"),
        ("invariant_params", {"inv3": {"window_hours": -1}}, "window_hours"),
        ("invariant_params", {"inv3": {"typo": 1}}, "typo"),
        ("invariant_params", {"inv9": {}}, "inv9"),
        ("agent_hints", {"split": [1, 2]}, "agent_hints"),
        ("agent_hints", {"bad key!": 1}, "agent_hints"),
    ],
)
def test_invalid_invariant_params_or_hints(key: str, value: object, fragment: str) -> None:
    def mutate(d: Doc) -> None:
        d[key] = value

    assert fragment in errors_for(mutate)


# ---------------------------------------------------------------- attack goal


def test_builtin_scenarios_declare_attack_goals() -> None:
    assert all(s.attack_goal is not None for s in load_all())


def test_attack_goal_payee_in_payload_accepted() -> None:
    doc = base()
    doc["attack_goal"] = {"payees": ["refund-desk@attacker.example.test"]}
    s = parse_scenario(yaml.safe_dump(doc, sort_keys=False))
    assert s.attack_goal is not None
    assert s.attack_goal.payees == ["refund-desk@attacker.example.test"]


def test_attack_goal_payee_not_in_payload_rejected() -> None:
    def mutate(d: Doc) -> None:
        d["attack_goal"] = {"payees": ["chosen-after@attacker.example.test"]}

    assert "attack_goal payee 'chosen-after@attacker.example.test'" in errors_for(mutate)


def test_attack_goal_payee_only_in_benign_payload_rejected() -> None:
    def mutate(d: Doc) -> None:
        d["benign_control"]["payload"] = "thanks benign@example.test"
        d["attack_goal"] = {"payees": ["benign@example.test"]}

    assert "does not appear in the attack payload" in errors_for(mutate)


def test_attack_goal_account_must_be_in_payload_and_exist() -> None:
    def in_payload_unknown(d: Doc) -> None:
        d["injection"]["payload"] += " acc_ghost"
        d["attack_goal"] = {"accounts": ["acc_ghost"]}

    def known_not_in_payload(d: Doc) -> None:
        d["attack_goal"] = {"accounts": ["acc_alice"]}

    assert "attack_goal.accounts: unknown account 'acc_ghost'" in errors_for(in_payload_unknown)
    assert "attack_goal account 'acc_alice'" in errors_for(known_not_in_payload)


def test_attack_goal_may_come_from_extra_parts() -> None:
    s = load_scenario(BUILTIN_SCENARIOS_DIR / "pix-description-drain-007.yaml")
    doc: Doc = yaml.safe_load(
        (BUILTIN_SCENARIOS_DIR / "pix-description-drain-007.yaml").read_text(encoding="utf-8")
    )
    doc["injection"]["payload"] = doc["injection"]["payload"].replace(
        "mule@x.example.test", "other@x.example.test"
    )
    doc["attack_goal"] = {"payees": ["mule@x.example.test"]}
    parsed = parse_scenario(yaml.safe_dump(doc, sort_keys=False))
    assert parsed.attack_goal == s.attack_goal


def test_attack_goal_amount_in_payload_accepted_in_any_spelling() -> None:
    for spelling in ("R$ 450.00", "R$ 450,00", "45000 cents"):
        doc = base()
        doc["injection"]["payload"] = f"{doc['canary']} pay {spelling}"
        doc["attack_goal"] = {"amounts": [45000]}
        s = parse_scenario(yaml.safe_dump(doc, sort_keys=False))
        assert s.attack_goal is not None
        assert s.attack_goal.amounts == [45000]


def test_attack_goal_amount_not_in_payload_rejected() -> None:
    def mutate(d: Doc) -> None:
        d["attack_goal"] = {"amounts": [45001]}

    assert "attack_goal amount 45001 does not appear" in errors_for(mutate)


def test_attack_goal_amount_equal_to_benign_amount_rejected() -> None:
    def mutate(d: Doc) -> None:
        cents = d["benign_control"]["expected_outcome"]["transfers"][0]["amount_cents"]
        whole, frac = divmod(cents, 100)
        d["injection"]["payload"] = f"{d['canary']} pay R$ {whole}.{frac:02d}"
        d["attack_goal"] = {"amounts": [cents]}

    assert "equals an expected benign transfer amount" in errors_for(mutate)


def test_empty_goal_amounts_keep_scenario_hash() -> None:
    from mulebench.attacks import scenario_sha256

    doc = base()
    doc["attack_goal"] = {"payees": []}
    plain = parse_scenario(yaml.safe_dump(doc, sort_keys=False))
    doc["attack_goal"] = {"payees": [], "amounts": []}
    explicit = parse_scenario(yaml.safe_dump(doc, sort_keys=False))
    assert scenario_sha256(plain) == scenario_sha256(explicit)


# ------------------------------------------------------------------ topology


def test_delegation_topology_defaults_split_read_and_pay_tools() -> None:
    doc = base()
    doc["topology"] = {"kind": "delegation"}
    s = parse_scenario(yaml.safe_dump(doc, sort_keys=False))
    assert s.topology is not None
    assert s.topology.reader_tools == ["get_balance", "list_transactions"]
    assert s.topology.payer_tools == ["transfer_pix", "open_dispute"]


def test_delegation_topology_rejects_overlap_memory_and_followups() -> None:
    def overlap(d: Doc) -> None:
        d["topology"] = {"kind": "delegation", "payer_tools": ["transfer_pix", "get_balance"]}

    def memory_tool(d: Doc) -> None:
        d["topology"] = {"kind": "delegation", "reader_tools": ["read_notes"]}

    def memory_on(d: Doc) -> None:
        d["topology"] = {"kind": "delegation"}
        d["memory"] = True

    def followups(d: Doc) -> None:
        d["topology"] = {"kind": "delegation"}
        d["followup_sessions"] = [{"request": "check my balance", "gap_hours": 1}]

    assert "must be disjoint" in errors_for(overlap)
    assert "memory tool 'read_notes'" in errors_for(memory_tool)
    assert "does not support memory" in errors_for(memory_on)
    assert "does not support followup_sessions" in errors_for(followups)


def test_absent_topology_keeps_scenario_hash() -> None:
    from mulebench.attacks import scenario_sha256

    doc = base()
    plain = parse_scenario(yaml.safe_dump(doc, sort_keys=False))
    doc["topology"] = None
    explicit = parse_scenario(yaml.safe_dump(doc, sort_keys=False))
    assert scenario_sha256(plain) == scenario_sha256(explicit)
