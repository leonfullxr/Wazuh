"""Parse IAM policy document blocks from Terraform configuration."""

from __future__ import annotations

import re
from typing import cast


def _bracket_list_contents(text: str, open_index: int) -> tuple[str, int]:
    if open_index >= len(text) or text[open_index] != "[":
        raise ValueError("expected opening bracket")
    depth = 0
    for index in range(open_index, len(text)):
        char = text[index]
        if char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0:
                return text[open_index + 1 : index], index + 1
    raise ValueError("unterminated values list")


def _parse_values_list(raw: str) -> list[str]:
    parts = [part.strip() for part in raw.split(",") if part.strip()]
    values: list[str] = []
    for part in parts:
        if part.startswith('"') and part.endswith('"'):
            values.append(part[1:-1])
        else:
            values.append(part)
    return values


def parse_policy_document_conditions(block: str) -> list[dict[str, object]]:
    conditions: list[dict[str, object]] = []
    cursor = 0
    while True:
        start = block.find("condition {", cursor)
        if start < 0:
            break
        test = re.search(r'test\s*=\s*"([^"]+)"', block[start:])
        variable = re.search(r'variable\s*=\s*"([^"]+)"', block[start:])
        values_match = re.search(r"values\s*=\s*\[", block[start:])
        if not test or not variable or not values_match:
            cursor = start + len("condition {")
            continue
        bracket_index = start + values_match.end() - 1
        raw_values, end = _bracket_list_contents(block, bracket_index)
        conditions.append(
            {
                "test": test.group(1),
                "variable": variable.group(1),
                "values": _parse_values_list(raw_values),
            }
        )
        cursor = end
    return conditions


def policy_document_to_iam_json(block: str) -> dict[str, object]:
    """Build IAM policy JSON from an aws_iam_policy_document HCL block."""
    statements: list[dict[str, object]] = []
    for statement in re.finditer(r"statement\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}", block, re.DOTALL):
        body = statement.group(1)
        effect = re.search(r'effect\s*=\s*"([^"]+)"', body)
        actions_match = re.search(r"actions\s*=\s*\[([^\]]+)\]", body)
        if not effect or not actions_match:
            continue
        actions = [
            part.strip().strip('"') for part in actions_match.group(1).split(",") if part.strip()
        ]
        conditions = parse_policy_document_conditions(body)
        condition: dict[str, dict[str, object]] = {}
        for entry in conditions:
            test = str(entry["test"])
            variable = str(entry["variable"])
            values = cast(list[str], entry["values"])
            operator = {
                "StringEquals": "StringEquals",
                "ArnLike": "ArnLike",
                "ArnEquals": "ArnEquals",
            }.get(test)
            if operator is None:
                continue
            condition.setdefault(operator, {})[variable] = values[0] if len(values) == 1 else values
        statement_json: dict[str, object] = {
            "Effect": effect.group(1),
            "Action": actions,
        }
        resources_match = re.search(r"resources\s*=\s*\[([^\]]+)\]", body)
        if resources_match:
            resources = [
                part.strip() for part in resources_match.group(1).split(",") if part.strip()
            ]
            statement_json["Resource"] = resources[0] if len(resources) == 1 else resources
        principals_match = re.search(r"identifiers\s*=\s*\[([^\]]+)\]", body)
        if principals_match:
            statement_json["Principal"] = {
                "Service": [
                    part.strip().strip('"')
                    for part in principals_match.group(1).split(",")
                    if part.strip()
                ][0]
            }
        if condition:
            statement_json["Condition"] = condition
        statements.append(statement_json)
    return {"Version": "2012-10-17", "Statement": statements}
