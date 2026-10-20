"""Durable persistence for qualification setting mutations; no AWS operations."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_JOURNAL_SCHEMA = "ai-soc.qualification-settings.v1"


@dataclass(frozen=True)
class PreparedMutation:
    before: Any
    after: Any


@dataclass(frozen=True)
class UncertainMutation:
    before: Any
    after: Any
    deadline: datetime
    target: Any


@dataclass(frozen=True)
class AppliedMutation:
    before: Any
    after: Any


type MutationEntry = PreparedMutation | UncertainMutation | AppliedMutation


class SettingsJournal:
    """Durably retain exact before/after state until restoration succeeds."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.entries: dict[str, MutationEntry] = {}
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            if (
                not isinstance(data, dict)
                or data.get("schema") != _JOURNAL_SCHEMA
                or not isinstance(data.get("entries"), dict)
            ):
                raise ValueError("invalid qualification settings journal")
            self.entries = {name: _decode_entry(value) for name, value in data["entries"].items()}

    @property
    def pending(self) -> dict[str, MutationEntry]:
        return dict(self.entries)

    def record(self, name: str, before: Any, after: Any) -> None:
        if name in self.entries:
            raise RuntimeError(f"settings restoration is already pending for {name}")
        self.entries[name] = PreparedMutation(before, after)
        self._flush()

    def restored(self, name: str) -> None:
        if name not in self.entries:
            raise KeyError(name)
        del self.entries[name]
        self._flush()

    def update_after(self, name: str, after: Any) -> None:
        if name not in self.entries:
            raise KeyError(name)
        entry = self.entries[name]
        if isinstance(entry, UncertainMutation):
            self.entries[name] = UncertainMutation(
                entry.before, after, entry.deadline, entry.target
            )
        elif isinstance(entry, AppliedMutation):
            self.entries[name] = AppliedMutation(entry.before, after)
        else:
            self.entries[name] = PreparedMutation(entry.before, after)
        self._flush()

    def mark_uncertain(self, name: str, *, until: datetime, target: Any) -> None:
        if name not in self.entries:
            raise KeyError(name)
        entry = self.entries[name]
        self.entries[name] = UncertainMutation(
            before=entry.before,
            after=entry.after,
            deadline=until.astimezone(UTC),
            target=target,
        )
        self._flush()

    def mutation_succeeded(self, name: str) -> None:
        if name not in self.entries:
            raise KeyError(name)
        entry = self.entries[name]
        self.entries[name] = AppliedMutation(entry.before, entry.after)
        self._flush()

    def _flush(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.path.parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(
                    {
                        "schema": _JOURNAL_SCHEMA,
                        "entries": {
                            name: _encode_entry(entry) for name, entry in self.entries.items()
                        },
                    },
                    stream,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            directory = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


def _decode_entry(value: Any) -> MutationEntry:
    if not isinstance(value, dict) or "before" not in value or "after" not in value:
        raise ValueError("invalid qualification settings journal entry")
    state = value.get("state", "prepared")
    if state == "uncertain" or "uncertain_until" in value or "in_flight_target" in value:
        deadline = value.get("uncertain_until")
        if not isinstance(deadline, str) or "in_flight_target" not in value:
            raise ValueError("uncertain journal entries require deadline and target")
        try:
            parsed = datetime.fromisoformat(deadline.replace("Z", "+00:00")).astimezone(UTC)
        except ValueError as exc:
            raise ValueError("uncertain journal entry has an invalid deadline") from exc
        return UncertainMutation(value["before"], value["after"], parsed, value["in_flight_target"])
    if state == "prepared":
        return PreparedMutation(value["before"], value["after"])
    if state == "applied":
        return AppliedMutation(value["before"], value["after"])
    raise ValueError("invalid qualification settings journal state")


def _encode_entry(entry: MutationEntry) -> dict[str, Any]:
    value: dict[str, Any] = {"before": entry.before, "after": entry.after}
    if isinstance(entry, UncertainMutation):
        value.update(
            state="uncertain",
            uncertain_until=entry.deadline.astimezone(UTC).isoformat(),
            in_flight_target=entry.target,
        )
    elif isinstance(entry, AppliedMutation):
        value["state"] = "applied"
    else:
        value["state"] = "prepared"
    return value
