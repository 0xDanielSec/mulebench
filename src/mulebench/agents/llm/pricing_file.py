"""Local, dated price table for routed providers (OpenRouter).

The table is a TOML file the operator edits (default `pricing/openrouter.toml`):

    as_of = "2026-11-16"
    source = "where the prices were read"

    [[price]]
    model = "vendor/model"
    host = "HostName"          # the pinned host provider; "TBD" = not pinned yet
    input_per_mtok = 0.10      # USD per million input tokens
    output_per_mtok = 0.30     # USD per million output tokens

Prices differ between host providers, so an entry is keyed by (model, host).
An entry whose host is "TBD" never matches: a run cannot start until the
host is pinned and priced. The run report stores `as_of`, the file's sha256
and the price used. The cost cap is enforced with these prices.
"""

from __future__ import annotations

import hashlib
import tomllib
from collections.abc import Callable
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from mulebench.agents.base import TokenUsage
from mulebench.agents.llm.pricing import Price

DEFAULT_PRICING_FILE = Path("pricing") / "openrouter.toml"
UNPINNED_HOST = "TBD"


class PriceFileError(ValueError):
    pass


class _Entry(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    model: str = Field(min_length=1)
    host: str = Field(min_length=1)
    input_per_mtok: float = Field(ge=0)
    output_per_mtok: float = Field(ge=0)
    note: str = ""


class _File(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    as_of: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    source: str = Field(min_length=1)
    price: list[_Entry] = []


class PriceTable(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    as_of: str
    source: str
    sha256: str
    entries: tuple[_Entry, ...]

    def price(self, model: str, host: str) -> Price | None:
        """The price of `model` served by `host`; None if unpriced or unpinned."""
        if host.casefold() == UNPINNED_HOST.casefold():
            return None
        for e in self.entries:
            if e.model == model and e.host.casefold() == host.casefold():
                return Price(
                    input_per_mtok=e.input_per_mtok,
                    output_per_mtok=e.output_per_mtok,
                    cache_read_per_mtok=0.0,
                )
        return None

    def models(self) -> list[str]:
        return sorted({e.model for e in self.entries})

    def any_price(self, model: str) -> Price | None:
        """For estimates before a host is pinned: the highest listed price."""
        rows = [e for e in self.entries if e.model == model]
        if not rows:
            return None
        top = max(rows, key=lambda e: (e.output_per_mtok, e.input_per_mtok))
        return Price(
            input_per_mtok=top.input_per_mtok,
            output_per_mtok=top.output_per_mtok,
            cache_read_per_mtok=0.0,
        )


def load_price_table(path: Path) -> PriceTable:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise PriceFileError(f"cannot read price table {path}: {exc.strerror}") from None
    try:
        data = _File.model_validate(tomllib.loads(raw.decode("utf-8")))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise PriceFileError(f"{path}: not valid TOML: {exc}") from None
    except ValidationError as exc:
        raise PriceFileError(
            f"{path}: {exc.errors()[0]['msg']} at {exc.errors()[0]['loc']}"
        ) from None
    keys = [(e.model, e.host.casefold()) for e in data.price]
    if len(keys) != len(set(keys)):
        raise PriceFileError(f"{path}: duplicate (model, host) entries")
    return PriceTable(
        as_of=data.as_of,
        source=data.source,
        sha256=hashlib.sha256(raw).hexdigest(),
        entries=tuple(data.price),
    )


def fixed_pricer(price: Price) -> Callable[[TokenUsage, str], float | None]:
    """A cost function with one price, whatever model name the response carries
    (the served model is checked against the requested one separately)."""

    def cost(usage: TokenUsage, served_model: str) -> float | None:
        total = (
            usage.input_tokens * price.input_per_mtok + usage.output_tokens * price.output_per_mtok
        ) / 1_000_000
        return round(total, 6)

    return cost
