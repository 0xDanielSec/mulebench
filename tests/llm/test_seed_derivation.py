"""Per-trial seed derivation: each trial_key gets its own seed."""

from __future__ import annotations

import hashlib

from mulebench.agents.llm.seeds import SEED_DERIVATION, SEED_MODULUS, derive_seed
from mulebench.harness.runner import trial_key


def test_scheme_is_named_and_documented() -> None:
    assert SEED_DERIVATION == "sha256_trial_key_v1"
    assert SEED_MODULUS == 2**31


def test_seed_is_base_plus_trial_key_hash_mod_2_31() -> None:
    key = trial_key("s-001", "baseline", "vulnerable", "attack", 3)
    h = int.from_bytes(hashlib.sha256(key.encode("utf-8")).digest()[:8], "big")
    assert derive_seed(1000, key) == (1000 + h) % 2**31


def test_seed_is_stable_and_in_range() -> None:
    key = trial_key("s-001", "baseline", "vulnerable", "attack", 0)
    assert derive_seed(0, key) == derive_seed(0, key)
    assert 0 <= derive_seed(2**40, key) < 2**31


def test_every_component_of_the_trial_key_changes_the_seed() -> None:
    base = ("s-004", "baseline", "vulnerable", "attack", 0)
    seeds = {derive_seed(1000, trial_key(*base))}
    for i, other in enumerate(("s-008", "data_not_instructions", "hardened", "benign", 1)):
        parts = list(base)
        parts[i] = other
        seeds.add(derive_seed(1000, trial_key(*parts)))  # type: ignore[arg-type]
    assert len(seeds) == 6


def test_base_seed_changes_the_seed() -> None:
    key = trial_key("s-004", "baseline", "vulnerable", "attack", 0)
    assert derive_seed(0, key) != derive_seed(1000, key)
