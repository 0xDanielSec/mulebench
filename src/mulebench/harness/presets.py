"""Guard presets by name.

A preset is a set of guard names. Guards are always installed in the canonical
order of `GUARD_NAMES`, so a preset's behavior does not depend on how its names
were listed. Named presets:

    vulnerable  no guards
    hardened    account_ownership, require_authorization, human_confirmation
    strict      every guard and transformer

Ablation presets are generated: `none`, `all`, `only:<guard>` and
`all-minus:<guard>`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from mulebench.tools import (
    AccountOwnership,
    Confirmer,
    Guard,
    HumanConfirmation,
    NewPayeeGuard,
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

NAMED_PRESETS: Mapping[str, frozenset[str]] = {
    "vulnerable": frozenset(),
    "hardened": frozenset({"account_ownership", "require_authorization", "human_confirmation"}),
    "strict": frozenset(GUARD_NAMES),
}

DEFAULT_PRESETS: tuple[str, ...] = ("vulnerable", "hardened")


class UnknownPreset(ValueError):
    def __init__(self, name: str) -> None:
        super().__init__(
            f"unknown preset {name!r}; choose from {', '.join(NAMED_PRESETS)}, none, all, "
            "only:<guard>, all-minus:<guard> (guards: " + ", ".join(GUARD_NAMES) + ")"
        )


def ablation_presets() -> tuple[str, ...]:
    """none, every guard alone, every guard removed from the full set, all."""
    return (
        "none",
        *(f"only:{g}" for g in GUARD_NAMES),
        *(f"all-minus:{g}" for g in GUARD_NAMES),
        "all",
    )


def preset_guard_names(name: str) -> tuple[str, ...]:
    """Guard names of a preset, in canonical order. Raises UnknownPreset."""
    if name in NAMED_PRESETS:
        chosen = NAMED_PRESETS[name]
    elif name == "none":
        chosen = frozenset()
    elif name == "all":
        chosen = frozenset(GUARD_NAMES)
    elif name.startswith("only:") and name.removeprefix("only:") in GUARD_NAMES:
        chosen = frozenset({name.removeprefix("only:")})
    elif name.startswith("all-minus:") and name.removeprefix("all-minus:") in GUARD_NAMES:
        chosen = frozenset(GUARD_NAMES) - {name.removeprefix("all-minus:")}
    else:
        raise UnknownPreset(name)
    return tuple(g for g in GUARD_NAMES if g in chosen)


@dataclass(frozen=True)
class GuardSet:
    guards: tuple[Guard, ...]
    transformers: tuple[ResultTransformer, ...]


def build_guard_set(
    name: str,
    confirmer: Confirmer,
    trial_key: str,
    *,
    threshold_cents: int = DEFAULT_CONFIRMATION_THRESHOLD_CENTS,
) -> GuardSet:
    names = preset_guard_names(name)
    factories: Mapping[str, Guard] = {
        "account_ownership": AccountOwnership(),
        "require_authorization": RequireAuthorization(),
        "session_spend_cap": SessionSpendCap(),
        "velocity": VelocityGuard(confirmer),
        "new_payee": NewPayeeGuard(confirmer),
        "human_confirmation": HumanConfirmation(threshold_cents, confirmer),
    }
    guards = tuple(factories[g] for g in names if g in factories)
    transformers: tuple[ResultTransformer, ...] = ()
    if "untrusted_content_marking" in names:
        transformers = (UntrustedContentMarking(marking_nonce(trial_key)),)
    return GuardSet(guards=guards, transformers=transformers)
