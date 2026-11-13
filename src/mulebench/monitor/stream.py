"""Streaming mode: process events as they arrive.

After each event the monitor re-runs the checks of the sessions the event can
change (see `MonitorState.apply`) and diffs the result against the alerts it
already emitted:

- a new alert is emitted `provisional`;
- an alert whose evidence changed is emitted again with its current status;
- an emitted alert that no longer holds is emitted `retracted`;
- a provisional alert becomes `firm` once the watermark (latest event time
  seen minus the grace period) passes its time.

Consumers keep the latest line per `alert_id`. `flush()` ends the stream and
makes every open alert firm. Because the checks are the batch checks, the
alerts open after `flush()` equal the batch alerts for the same events when
no event is later than the grace period; a later event is still applied, and
can retract an alert that was already firm.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from datetime import datetime, timedelta

from mulebench.ledger.models import LedgerSnapshot
from mulebench.monitor.alerts import Alert, sort_alerts
from mulebench.monitor.engine import (
    ConfigFor,
    SessionConfig,
    constant_config,
    evaluate_orphans,
    evaluate_session,
)
from mulebench.monitor.events import Event, LedgerAccount, LedgerAuthorization, LedgerTransfer
from mulebench.monitor.state import MonitorState

DEFAULT_GRACE = timedelta(minutes=5)
ORPHANS = "\x00orphans"  # pseudo-session key of the orphan-transfer alerts


class StreamingMonitor:
    def __init__(
        self, config_for: ConfigFor | None = None, grace: timedelta = DEFAULT_GRACE
    ) -> None:
        self.state = MonitorState()
        self.config_for = config_for or constant_config(SessionConfig())
        self.grace = grace
        # Latest emitted version of every alert, by owner key then alert id.
        self.open: dict[str, dict[str, Alert]] = {}

    @property
    def watermark(self) -> datetime | None:
        m = self.state.max_ts
        return None if m is None else m - self.grace

    def feed(self, e: Event) -> list[Alert]:
        affected = self.state.apply(e)
        if isinstance(e, LedgerAccount | LedgerAuthorization | LedgerTransfer):
            # Ownership and foreign amounts (disclosure) can change for anyone.
            affected = set(self.state.sessions)
        out: list[Alert] = []
        snap = self.state.snapshot()
        for sid in sorted(affected):
            out += self._diff(sid, self._current(sid, snap))
        out += self._diff(ORPHANS, {a.alert_id: a for a in evaluate_orphans(self.state)})
        out += self._promote(self.watermark)
        return out

    def flush(self) -> list[Alert]:
        return self._promote(None)

    def run(self, events: Iterable[Event]) -> Iterator[Alert]:
        for e in events:
            yield from self.feed(e)
        yield from self.flush()

    def alerts(self) -> list[Alert]:
        """Open (not retracted) alerts, latest version of each."""
        return sort_alerts(a for owned in self.open.values() for a in owned.values())

    # ------------------------------------------------------------ internals

    def _current(self, sid: str, snap: LedgerSnapshot) -> dict[str, Alert]:
        found = evaluate_session(self.state, sid, self.config_for(sid), snap)
        return {a.alert_id: a for a in found}

    def _diff(self, owner: str, current: dict[str, Alert]) -> list[Alert]:
        before = self.open.setdefault(owner, {})
        out: list[Alert] = []
        for aid in sorted(set(before) - set(current)):
            out.append(before.pop(aid).model_copy(update={"status": "retracted"}))
        for aid in sorted(current):
            prev = before.get(aid)
            status = "provisional" if prev is None else prev.status
            alert = current[aid].model_copy(update={"status": status})
            if prev != alert:
                before[aid] = alert
                out.append(alert)
        return out

    def _promote(self, watermark: datetime | None) -> list[Alert]:
        out: list[Alert] = []
        for owned in self.open.values():
            for aid, a in sorted(owned.items()):
                if a.status == "provisional" and (watermark is None or a.ts <= watermark):
                    owned[aid] = firm = a.model_copy(update={"status": "firm"})
                    out.append(firm)
        return out
