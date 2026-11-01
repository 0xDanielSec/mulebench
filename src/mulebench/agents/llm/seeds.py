"""Per-trial sampling seed for OpenAI-compatible servers.

Scheme `sha256_trial_key_v1`:

    seed = (base + int.from_bytes(sha256(trial_key)[:8], "big")) mod 2**31

`trial_key` is `scenario/prompt_variant/preset/variant/tNNN`, so every cell and
trial gets its own seed. Before this scheme trial t used `base + t` in every
cell, which made trials with the same index share their first model call
across scenarios with an identical first request (pilot 01, finding F1).
Reports from that time have no `seed_derivation` field.
"""

from __future__ import annotations

import hashlib

SEED_DERIVATION = "sha256_trial_key_v1"
SEED_MODULUS = 2**31  # fits a signed 32-bit seed on every server we know of


def derive_seed(base: int, trial_key: str) -> int:
    digest = hashlib.sha256(trial_key.encode("utf-8")).digest()
    return (base + int.from_bytes(digest[:8], "big")) % SEED_MODULUS
