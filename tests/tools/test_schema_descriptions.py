"""What models see of the tools: complete, neutral descriptions and specific errors."""

from __future__ import annotations

import re
from typing import Any

import pytest

from mulebench.attacks import load_builtin
from mulebench.tools.client import model_tool_schemas, tool_schema_sha256
from mulebench.tools.registry import TOOLS, describe_validation_error

# Defensive or instruction-handling language belongs to the prompt-defense axis
# (prompt variants), never to the baseline tool descriptions.
FORBIDDEN = (
    "ignore",
    "instruction",
    "follow",
    "obey",
    "trust",
    "inject",
    "malicious",
    "attack",
    "suspicious",
    "phishing",
    "fraud",
    "scam",
    "security",
    "safe",
    "verify",
    "do not",
    "don't",
    "never",
    "must not",
    "warning",
    "careful",
    "caution",
    "treat",
    "data only",
)


def descriptions(schema: Any) -> list[str]:
    out: list[str] = []
    if isinstance(schema, dict):
        for key, value in schema.items():
            if key == "description" and isinstance(value, str):
                out.append(value)
            else:
                out += descriptions(value)
    elif isinstance(schema, list):
        for value in schema:
            out += descriptions(value)
    return out


def all_texts() -> list[str]:
    texts: list[str] = []
    for tool in model_tool_schemas():
        texts.append(tool["description"])
        texts += descriptions(tool["input_schema"])
    return texts


@pytest.mark.parametrize("word", FORBIDDEN)
def test_descriptions_are_neutral(word: str) -> None:
    pattern = re.compile(rf"\b{re.escape(word)}", re.IGNORECASE)
    hits = [t for t in all_texts() if pattern.search(t)]
    assert hits == [], f"{word!r} in tool descriptions: {hits}"


def test_every_input_field_is_described_and_no_developer_notes() -> None:
    for tool in model_tool_schemas():
        schema = tool["input_schema"]
        assert "description" not in schema, tool["name"]  # e.g. the idempotency note
        for name, field in schema["properties"].items():
            assert field.get("description"), f"{tool['name']}.{name}"
    assert "idempotency" not in " ".join(all_texts()).lower()


def test_examples_do_not_reuse_scenario_values() -> None:
    text = " ".join(all_texts())
    for s in load_builtin():
        dumped = s.model_dump_json()
        for token in re.findall(r'"(auth_[^"]+|tx_[^"]+|acc_[^"]+)"', text):
            assert f'"{token}"' not in dumped, (s.id, token)
        for amount in re.findall(r"\b\d{4,}\b", text):
            assert not re.search(rf":\s?{amount}\b", dumped), (s.id, amount)


def test_schema_hash_is_stable_and_tracks_content() -> None:
    assert tool_schema_sha256() == tool_schema_sha256()
    assert len(tool_schema_sha256()) == 64


# ------------------------------------------------------- invalid_input


def message(tool: str, args: dict[str, Any]) -> str:
    from pydantic import ValidationError

    with pytest.raises(ValidationError) as info:
        TOOLS[tool].input_model.model_validate(args)
    return describe_validation_error(info.value)


def test_specific_messages_without_the_input() -> None:
    good = {"from_account_id": "a", "to_pix_key": "k"}
    assert message("transfer_pix", {**good, "amount_cents": "120000"}) == (
        "invalid arguments: amount_cents must be a JSON integer"
    )
    assert message("transfer_pix", {**good, "amount_cents": 0}) == (
        "invalid arguments: amount_cents must be greater than 0"
    )
    assert message("transfer_pix", good) == "invalid arguments: amount_cents is required"
    assert message("list_transactions", {"account_id": "a", "limit": 99}) == (
        "invalid arguments: limit must be at most 50"
    )
    assert message("get_balance", {"account_id": "a", "x": "SECRET-INPUT"}) == (
        "invalid arguments: x is not an accepted argument"
    )
    assert "120000" not in message("transfer_pix", {**good, "amount_cents": "120000"})
