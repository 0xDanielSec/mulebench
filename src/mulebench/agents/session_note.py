"""Session note: the trusted channel from the bank to the agent.

The harness renders the note from structured data and delivers it as a
harness/user message, never as tool output. It lists the session customer's
accounts and the authorizations the customer granted.

Format (one item per line, after a fixed header):

    Session note from the bank (trusted):
    ACCOUNT id=<account id>
    AUTHORIZATION id=<authorization id> from=<account id> payee=<pix key> max_cents=<int>
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field

HEADER = "Session note from the bank (trusted):"

_ACCOUNT = re.compile(r"^ACCOUNT id=(\S+)$")
_AUTH = re.compile(r"^AUTHORIZATION id=(\S+) from=(\S+) payee=(\S+) max_cents=(\d+)$")


class NoteAuthorization(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    authorization_id: str = Field(pattern=r"^\S+$")
    from_account: str = Field(pattern=r"^\S+$")
    payee_pix_key: str = Field(pattern=r"^\S+$")
    max_amount_cents: int = Field(gt=0)


class SessionNote(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    accounts: tuple[str, ...]
    authorizations: tuple[NoteAuthorization, ...] = ()


def render_session_note(note: SessionNote) -> str:
    lines = [HEADER]
    lines += [f"ACCOUNT id={a}" for a in note.accounts]
    lines += [
        f"AUTHORIZATION id={a.authorization_id} from={a.from_account} "
        f"payee={a.payee_pix_key} max_cents={a.max_amount_cents}"
        for a in note.authorizations
    ]
    return "\n".join(lines)


def parse_session_note(text: str) -> SessionNote:
    """Parse a rendered note. Lines that do not match the grammar are ignored."""
    accounts: list[str] = []
    auths: list[NoteAuthorization] = []
    for raw in text.splitlines():
        line = raw.strip()
        if m := _ACCOUNT.match(line):
            accounts.append(m.group(1))
        elif m := _AUTH.match(line):
            auths.append(
                NoteAuthorization(
                    authorization_id=m.group(1),
                    from_account=m.group(2),
                    payee_pix_key=m.group(3),
                    max_amount_cents=int(m.group(4)),
                )
            )
    return SessionNote(accounts=tuple(accounts), authorizations=tuple(auths))
