"""Evaluate DynamoDB ConditionExpression strings used in unit-test fakes."""

from __future__ import annotations

from typing import cast


def evaluate_condition(
    item: dict[str, object],
    condition: str,
    values: dict[str, object],
    names: dict[str, str] | None = None,
) -> bool:
    names = names or {}

    def field(name: str) -> object:
        return item.get(names.get(name, name))

    if "attribute_not_exists(pk)" in condition:
        return False
    if "remaining_tokens >= :tokens" in condition:
        if int(cast(int, field("remaining_tokens"))) < int(cast(int, values[":tokens"])):
            return False
    pairs = [
        ("lease_id = :lease", "lease_id", ":lease"),
        ("holder_id = :holder", "holder_id", ":holder"),
        ("fence = :fence", "fence", ":fence"),
        ("#state = :reserved", "state", ":reserved"),
        ("#state IN (:started, :reserved)", "state", (":started", ":reserved")),
        ("version = :old", "version", ":old"),
        ("question_id = :question", "question_id", ":question"),
    ]
    for fragment, attr, token in pairs:
        if fragment not in condition:
            continue
        value = field(attr)
        if isinstance(token, tuple):
            if value not in {values.get(entry) for entry in token}:
                return False
        elif value != values.get(token):
            return False
    if "expires_epoch > :now" in condition:
        return int(cast(int, field("expires_epoch"))) > int(cast(int, values[":now"]))
    if "attribute_not_exists(tokens_used)" in condition and "tokens_used <= :ceiling" in condition:
        used = field("tokens_used")
        tokens = int(cast(int, values[":tokens"]))
        limit = int(cast(int, values[":limit"]))
        ceiling = int(cast(int, values[":ceiling"]))
        first_write = used is None and tokens <= limit
        existing = used is not None and int(cast(int, used)) <= ceiling
        return first_write or existing
    if "tokens_used <= :ceiling" in condition:
        used = field("tokens_used")
        tokens = int(cast(int, values[":tokens"]))
        limit = int(cast(int, values[":limit"]))
        if used is None:
            return tokens <= limit
        return int(cast(int, used)) <= int(cast(int, values[":ceiling"]))
    if "tokens_used >= :refund_abs" in condition:
        used = int(cast(int, field("tokens_used") or 0))
        return used >= int(cast(int, values[":refund_abs"]))
    return True
