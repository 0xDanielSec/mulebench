"""Argument coercion at the LLM agent boundary.

Some models (e.g. Llama 3.1 via Ollama) send integers as JSON strings
(`"amount_cents": "120000"`). Mode `digit_strings` (the default) converts such a
value to an int, and only when:

- the tool's input schema declares the field `"type": "integer"`, and
- the value is a string of ASCII digits only (`^[0-9]+$`): no sign, no
  decimals, no separators, no whitespace, no currency.

`"1200.00"`, `"1.200"`, `"-5"`, `" 10"` or `"R$ 1200"` stay strings and fail
validation as before. The tools, ledger and invariants stay strict; they only
ever see real integers. Every coerced field is recorded per model call and per
trial. Mode `off` restores strict behavior.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, Literal

ArgCoercion = Literal["digit_strings", "off"]
ARG_COERCION_MODES: tuple[ArgCoercion, ...] = ("digit_strings", "off")
DEFAULT_ARG_COERCION: ArgCoercion = "digit_strings"

_DIGITS = re.compile(r"[0-9]+")


def coerce_args(
    args: Mapping[str, Any], input_schema: Mapping[str, Any] | None, mode: ArgCoercion
) -> tuple[dict[str, Any], list[str]]:
    """(arguments after coercion, names of the coerced fields, sorted)."""
    out = dict(args)
    if mode == "off" or input_schema is None:
        return out, []
    properties = input_schema.get("properties") or {}
    coerced: list[str] = []
    for name, value in args.items():
        spec = properties.get(name)
        if (
            isinstance(spec, Mapping)
            and spec.get("type") == "integer"
            and isinstance(value, str)
            and _DIGITS.fullmatch(value)
        ):
            out[name] = int(value)
            coerced.append(name)
    return out, sorted(coerced)
