"""Offline approval experiment. This module has no transport, credentials or Wazuh dispatcher."""

import hashlib
import json
import secrets
import sqlite3
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Preview:
    cluster: str
    agent: str
    duration_seconds: int
    expected_effect: str = "Display a simulated containment marker in the fixture"
    verification: str = "Read the marker from the fixture dispatcher"
    rollback: str = "Clear the fixture marker"


def proposal_digest(preview):
    payload = json.dumps(asdict(preview), sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


class ApprovalExperiment:
    """A trusted, local test host supplies the approver separately from the proposed action."""

    def __init__(self, database):
        self.db = sqlite3.connect(database)
        with self.db:
            self.db.execute("""CREATE TABLE IF NOT EXISTS approval (
                id TEXT PRIMARY KEY, digest TEXT NOT NULL, approver TEXT NOT NULL,
                expires_at INTEGER NOT NULL, state TEXT NOT NULL)""")

    def approve(self, preview, approver, now):
        if not approver.strip():
            raise ValueError("A host-authenticated approver is required")
        approval = secrets.token_urlsafe(24)
        with self.db:
            self.db.execute(
                "INSERT INTO approval VALUES (?, ?, ?, ?, 'approved')",
                (approval, proposal_digest(preview), approver, now + 60),
            )
        return approval

    def simulate(self, approval, preview, approver, now, *, interrupt=False):
        # Commit the consume record before the hypothetical boundary. A crash then requires reconciliation.
        with self.db:
            consumed = self.db.execute(
                """UPDATE approval SET state='outcome_unknown'
                WHERE id=? AND digest=? AND approver=? AND expires_at>? AND state='approved'""",
                (approval, proposal_digest(preview), approver, now),
            )
            if consumed.rowcount != 1:
                raise ValueError("Approval unavailable")
        if interrupt:
            return "outcome_unknown"
        with self.db:
            self.db.execute("UPDATE approval SET state='dispatched' WHERE id=?", (approval,))
        return "dispatched"

    def reconcile(self, approval, *, fixture_marker_present):
        with self.db:
            cursor = self.db.execute(
                """UPDATE approval SET state=? WHERE id=?
                AND state IN ('dispatched','outcome_unknown')""",
                ("verified" if fixture_marker_present else "outcome_unknown", approval),
            )
            if cursor.rowcount != 1:
                raise ValueError("No pending fixture result")

    def status(self, approval):
        row = self.db.execute("SELECT state FROM approval WHERE id=?", (approval,)).fetchone()
        return row[0] if row else "not_dispatched"
