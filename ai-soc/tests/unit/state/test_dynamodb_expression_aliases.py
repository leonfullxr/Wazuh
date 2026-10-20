from __future__ import annotations

import ast
import re
from pathlib import Path

_BARE_STATE = re.compile(r"(?<![#A-Za-z0-9_])state(?![A-Za-z0-9_])", re.IGNORECASE)
_EXPRESSION_NAME = re.compile(r"(?:condition|expression|update)", re.IGNORECASE)


def _string_parts(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.JoinedStr):
        return [
            part.value
            for part in node.values
            if isinstance(part, ast.Constant) and isinstance(part.value, str)
        ]
    return []


def _looks_like_expression(value: str) -> bool:
    return bool(
        re.search(
            r"\b(?:SET|ADD|REMOVE|DELETE|AND|OR|BETWEEN|begins_with|contains)\b|"
            r"(?:=|<=|>=|<>|<|>)|attribute_(?:not_)?exists\s*\(",
            value,
            re.IGNORECASE,
        )
    )


def _target_names(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        return [name for element in node.elts for name in _target_names(element)]
    return []


def _is_dynamodb_expression_key(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value in {
        "ConditionExpression",
        "UpdateExpression",
    }


def test_all_dynamodb_condition_and_update_expressions_alias_reserved_state() -> None:
    source = Path("src/ai_soc/state/dynamodb.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    expressions: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values, strict=True):
                if key is not None and _is_dynamodb_expression_key(key):
                    expressions.extend(
                        part for part in _string_parts(value) if _looks_like_expression(part)
                    )
        if isinstance(node, ast.Call):
            for keyword in node.keywords:
                if keyword.arg in {"ConditionExpression", "UpdateExpression"}:
                    expressions.extend(
                        part
                        for part in _string_parts(keyword.value)
                        if _looks_like_expression(part)
                    )
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            if value is None:
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            target_names = [name for target in targets for name in _target_names(target)]
            if any(_EXPRESSION_NAME.search(name) for name in target_names):
                for child in ast.walk(value):
                    expressions.extend(
                        part for part in _string_parts(child) if _looks_like_expression(part)
                    )

    assert expressions, "DynamoDB expressions should be checked"
    assert not [expression for expression in expressions if _BARE_STATE.search(expression)]
