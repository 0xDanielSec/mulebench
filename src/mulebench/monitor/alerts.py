"""Alerts: the monitor's output, written as JSON lines.

Evidence names ids, call sequence numbers, accounts and event field paths. It
never carries free text from the trace (final answers, descriptions, dispute
reasons), the same rule as `mulebench.disclosure`.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from datetime import datetime
from typing import Literal, TextIO

from pydantic import BaseModel, ConfigDict

from mulebench.monitor.rules import RULES_BY_ID, SEVERITY_ORDER, RuleFamily, Severity

AlertStatus = Literal["provisional", "firm", "retracted"]


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Evidence(_Model):
    call_seq: list[int] = []
    transfer_ids: list[str] = []
    accounts: list[str] = []
    fields: list[str] = []
    amount_cents: int | None = None


class Alert(_Model):
    v: Literal[1] = 1
    alert_id: str
    rule_id: str
    family: RuleFamily
    code: str
    severity: Severity
    status: AlertStatus
    # False for INV-4 when the operator stated no enforced confirmation
    # threshold: reported, but not a finding (same rule as the harness).
    applicable: bool = True
    session_id: str | None
    customer_id: str | None
    ts: datetime  # event time of the latest evidence
    evidence: Evidence
    detail: str


def alert_key(rule_id: str, session_id: str | None, evidence: Evidence) -> str:
    """Stable identity of an alert: same rule, session and evidence ids."""
    parts = [
        rule_id,
        session_id or "",
        ",".join(evidence.transfer_ids),
        ",".join(map(str, evidence.call_seq)) if not evidence.transfer_ids else "",
        ",".join(evidence.accounts) if not (evidence.transfer_ids or evidence.call_seq) else "",
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:24]


def make_alert(
    rule_id: str,
    *,
    session_id: str | None,
    customer_id: str | None,
    ts: datetime,
    evidence: Evidence,
    detail: str,
    status: AlertStatus = "firm",
    applicable: bool = True,
) -> Alert:
    rule = RULES_BY_ID[rule_id]
    return Alert(
        alert_id=alert_key(rule_id, session_id, evidence),
        rule_id=rule_id,
        family=rule.family,
        code=rule.code,
        severity=rule.severity,
        status=status,
        applicable=applicable,
        session_id=session_id,
        customer_id=customer_id,
        ts=ts,
        evidence=evidence,
        detail=detail,
    )


def at_least(alert: Alert, severity: Severity) -> bool:
    return SEVERITY_ORDER[alert.severity] >= SEVERITY_ORDER[severity]


def sort_alerts(alerts: Iterable[Alert]) -> list[Alert]:
    return sorted(alerts, key=lambda a: (a.ts, a.session_id or "", a.rule_id, a.alert_id))


def dump_alert(a: Alert) -> str:
    return json.dumps(a.model_dump(mode="json"), sort_keys=True)


def write_alerts(alerts: Iterable[Alert], out: TextIO) -> int:
    n = 0
    for a in alerts:
        out.write(dump_alert(a) + "\n")
        n += 1
    return n
