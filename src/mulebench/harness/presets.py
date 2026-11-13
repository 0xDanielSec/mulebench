"""Guard presets by name.

A preset is a set of guard names. Guards are always installed in the canonical
order of `GUARD_NAMES`, so a preset's behavior does not depend on how its names
were listed. Named presets:

    vulnerable  no guards
    hardened    account_ownership, require_authorization, human_confirmation
    strict      every guard and transformer of GUARD_NAMES
    memguard    hardened plus memory_write (memory scenarios; for ablation)
    delegation-defences
                structured_handoff, payer_payee_allowlist and payer_sees_request
                (delegation scenarios; for ablation)

`memory_write` is an optional guard: it is not part of GUARD_NAMES, so
`strict`, `all` and the generated ablation presets stay as in the pilots.
`only:memory_write` runs it alone. The delegation defences are optional in
the same way. `payer_payee_allowlist` is a tool guard; `structured_handoff`
and `payer_sees_request` are harness switches for delegation runs (see
mulebench.harness.delegation) and do nothing in single-agent runs.

Ablation presets are generated: `none`, `all`, `only:<guard>` and
`all-minus:<guard>`.

Guard parameters are a typed `GuardParams` object. Its string form, used in
preset names, reports and the CLI, is a suffix: `<preset>@<param>=<value>`, for
example `only:session_spend_cap@session_spend_cap=50000`. Unknown parameters,
non-integer or non-positive values, repeated parameters, and parameters for a
guard the preset does not install are rejected.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from mulebench.tools import (
    AccountOwnership,
    Confirmer,
    Guard,
    HumanConfirmation,
    MemoryWriteGuard,
    NewPayeeGuard,
    PayerPayeeAllowlist,
    RequireAuthorization,
    ResultTransformer,
    SessionSpendCap,
    UntrustedContentMarking,
    VelocityGuard,
    marking_nonce,
)
from mulebench.tools.guards import DEFAULT_CONFIRMATION_THRESHOLD_CENTS

GUARD_NAMES: tuple[str, ...] = (
    "account_ownership",
    "require_authorization",
    "session_spend_cap",
    "velocity",
    "new_payee",
    "human_confirmation",
    "untrusted_content_marking",
)

# Guards installed only by name, never by strict/all/ablation generation.
OPTIONAL_GUARDS: tuple[str, ...] = (
    "memory_write",
    "structured_handoff",
    "payer_payee_allowlist",
    "payer_sees_request",
)
DELEGATION_DEFENCES: tuple[str, ...] = (
    "structured_handoff",
    "payer_payee_allowlist",
    "payer_sees_request",
)
GUARD_ORDER: tuple[str, ...] = GUARD_NAMES + OPTIONAL_GUARDS

_HARDENED = frozenset({"account_ownership", "require_authorization", "human_confirmation"})
NAMED_PRESETS: Mapping[str, frozenset[str]] = {
    "vulnerable": frozenset(),
    "hardened": _HARDENED,
    "strict": frozenset(GUARD_NAMES),
    "memguard": _HARDENED | {"memory_write"},
    "delegation-defences": frozenset(DELEGATION_DEFENCES),
}

DEFAULT_PRESETS: tuple[str, ...] = ("vulnerable", "hardened")


class UnknownPreset(ValueError):
    def __init__(self, name: str) -> None:
        super().__init__(
            f"unknown preset {name!r}; choose from {', '.join(NAMED_PRESETS)}, none, all, "
            "only:<guard>, all-minus:<guard> (guards: " + ", ".join(GUARD_NAMES) + ")"
        )


class GuardParams(BaseModel):
    """Typed guard parameters. None means the guard's default."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    session_spend_cap: int | None = Field(default=None, gt=0)

    def suffix(self) -> str:
        """Serialization form: `@name=value` per set parameter, in field order."""
        return "".join(f"@{k}={v}" for k, v in self.model_dump().items() if v is not None)


class InvalidGuardParams(UnknownPreset):
    def __init__(self, name: str, reason: str) -> None:
        ValueError.__init__(self, f"invalid guard parameters in preset {name!r}: {reason}")


def parse_preset(name: str) -> tuple[str, GuardParams]:
    """Split a preset name into its base preset and typed GuardParams."""
    base, *parts = name.split("@")
    raw: dict[str, int] = {}
    for part in parts:
        key, sep, value = part.partition("=")
        if not sep or not key:
            raise InvalidGuardParams(name, f"expected <param>=<value>, got {part!r}")
        if key in raw:
            raise InvalidGuardParams(name, f"repeated parameter {key!r}")
        if not value.isdigit():
            raise InvalidGuardParams(name, f"{key} must be a positive integer, got {value!r}")
        raw[key] = int(value)
    try:
        params = GuardParams.model_validate(raw)
    except ValidationError as exc:
        reasons = "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors())
        raise InvalidGuardParams(name, reasons) from exc
    guards = _base_guard_names(base, name)
    for key, value in params.model_dump().items():
        if value is not None and key not in guards:
            raise InvalidGuardParams(name, f"{key} is not installed by preset {base!r}")
    return base, params


def ablation_presets() -> tuple[str, ...]:
    """none, every guard alone, every guard removed from the full set, all."""
    return (
        "none",
        *(f"only:{g}" for g in GUARD_NAMES),
        *(f"all-minus:{g}" for g in GUARD_NAMES),
        "all",
    )


def preset_guard_names(name: str) -> tuple[str, ...]:
    """Guard names of a preset (parameter suffix allowed), in canonical order.
    Raises UnknownPreset (InvalidGuardParams for bad parameters)."""
    base, _ = parse_preset(name)
    return _base_guard_names(base, name)


def _base_guard_names(name: str, full_name: str) -> tuple[str, ...]:
    if name in NAMED_PRESETS:
        chosen = NAMED_PRESETS[name]
    elif name == "none":
        chosen = frozenset()
    elif name == "all":
        chosen = frozenset(GUARD_NAMES)
    elif name.startswith("only:") and name.removeprefix("only:") in GUARD_ORDER:
        chosen = frozenset({name.removeprefix("only:")})
    elif name.startswith("all-minus:") and name.removeprefix("all-minus:") in GUARD_NAMES:
        chosen = frozenset(GUARD_NAMES) - {name.removeprefix("all-minus:")}
    else:
        raise UnknownPreset(full_name)
    return tuple(g for g in GUARD_ORDER if g in chosen)


@dataclass(frozen=True)
class GuardSet:
    guards: tuple[Guard, ...]
    transformers: tuple[ResultTransformer, ...]
    # Amount at or above which EVERY transfer goes to customer confirmation
    # (human_confirmation's threshold), or None. Handed to INV-4 as plain data.
    enforced_confirmation_cents: int | None = None
    # Delegation harness switches (no effect on single-agent runs).
    structured_handoff: bool = False
    payer_sees_request: bool = False


def build_guard_set(
    name: str,
    confirmer: Confirmer,
    trial_key: str,
    *,
    threshold_cents: int = DEFAULT_CONFIRMATION_THRESHOLD_CENTS,
) -> GuardSet:
    names = preset_guard_names(name)
    _, params = parse_preset(name)
    cap = (
        SessionSpendCap()
        if params.session_spend_cap is None
        else SessionSpendCap(params.session_spend_cap)
    )
    factories: Mapping[str, Guard] = {
        "account_ownership": AccountOwnership(),
        "require_authorization": RequireAuthorization(),
        "session_spend_cap": cap,
        "velocity": VelocityGuard(confirmer),
        "new_payee": NewPayeeGuard(confirmer),
        "human_confirmation": HumanConfirmation(threshold_cents, confirmer),
        "memory_write": MemoryWriteGuard(),
        "payer_payee_allowlist": PayerPayeeAllowlist(),
    }
    guards = tuple(factories[g] for g in names if g in factories)
    transformers: tuple[ResultTransformer, ...] = ()
    if "untrusted_content_marking" in names:
        transformers = (UntrustedContentMarking(marking_nonce(trial_key)),)
    enforced = threshold_cents if "human_confirmation" in names else None
    return GuardSet(
        guards=guards,
        transformers=transformers,
        enforced_confirmation_cents=enforced,
        structured_handoff="structured_handoff" in names,
        payer_sees_request="payer_sees_request" in names,
    )
