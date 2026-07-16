"""Answer shape templates (D56) - output-side structure for synthesis.

Shapes ride as transient context (never the static prelude) so the prompt-cache
prefix stays byte-stable. Selection is deterministic from intent heuristics;
verifiers still run on the rendered answer text.
"""
from __future__ import annotations

import re
from typing import Literal, Optional

ShapeName = Literal["triage_card", "incident_summary", "exec_rollup"]

_SHAPES: dict[str, dict[str, str]] = {
    "triage_card": {
        "en": (
            "Answer using this triage card shape (keep section headings exact):\n"
            "## Summary\n"
            "## Evidence\n"
            "## Impact\n"
            "## Recommendation\n"
            "## Triage\n"
            "Use Benign / Suspicious / Malicious plus a brief confidence note. "
            "Cite [alert:], [agg:], or [kb:] only for verified evidence."
        ),
        "es": (
            "Responde con esta ficha de triaje (mantén los encabezados exactos):\n"
            "## Resumen\n"
            "## Evidencia\n"
            "## Impacto\n"
            "## Recomendacion\n"
            "## Triaje\n"
            "Usa Benigno / Sospechoso / Malicioso mas una nota breve de confianza. "
            "Cita solo [alert:], [agg:] o [kb:] con evidencia verificada."
        ),
    },
    "incident_summary": {
        "en": (
            "Answer as an incident summary with these headings:\n"
            "## What happened\n"
            "## Scope\n"
            "## Timeline\n"
            "## Next steps\n"
            "Lead with datastore totals; cite [alert:]/[agg:]/[kb:] only."
        ),
        "es": (
            "Responde como resumen de incidente con estos encabezados:\n"
            "## Que ocurrio\n"
            "## Alcance\n"
            "## Linea de tiempo\n"
            "## Siguientes pasos\n"
            "Empieza con totales del datastore; cita solo [alert:]/[agg:]/[kb:]."
        ),
    },
    "exec_rollup": {
        "en": (
            "Answer as an executive rollup with these headings:\n"
            "## Headline\n"
            "## Numbers\n"
            "## Risk posture\n"
            "## Ask of leadership\n"
            "Keep it short; every number must come from a tool total or aggregation."
        ),
        "es": (
            "Responde como resumen ejecutivo con estos encabezados:\n"
            "## Titular\n"
            "## Numeros\n"
            "## Postura de riesgo\n"
            "## Peticion a liderazgo\n"
            "Se breve; cada numero debe venir de un total o agregacion de herramienta."
        ),
    },
}

_TRIAGE = re.compile(
    r"\b(investigat\w*|triage|explain\s+(this\s+)?alert|analy[sz]e\s+alert|"
    r"investigar|triar|explica(r)?\s+(esta\s+)?alerta)\b",
    re.I,
)
_INCIDENT = re.compile(
    r"\b(incident\s+summary|summarize\s+the\s+incident|resumen\s+del?\s+incidente|"
    r"resume\s+el\s+incidente)\b",
    re.I,
)
_EXEC = re.compile(
    r"\b(executive\s+(summary|rollup|brief)|board\s+summary|"
    r"resumen\s+ejecutivo|para\s+(la\s+)?direccion)\b",
    re.I,
)


def shape_text(name: ShapeName, lang: str = "en") -> str:
    block = _SHAPES[name]
    return block.get(lang) or block["en"]


def select_shape(
    question: str,
    *,
    playbook: bool = False,
    lang: str = "en",
) -> Optional[tuple[ShapeName, str]]:
    """Return (shape_name, instruction text) or None when no shape applies."""
    if playbook or _TRIAGE.search(question):
        name: ShapeName = "triage_card"
    elif _EXEC.search(question):
        name = "exec_rollup"
    elif _INCIDENT.search(question):
        name = "incident_summary"
    else:
        return None
    return name, shape_text(name, lang)


def transient_shape_messages(instruction: str) -> list[dict]:
    """User/assistant pair injected after language/env card, before the question."""
    return [
        {"role": "user", "content": [{"text": instruction}]},
        {"role": "assistant", "content": [{"text": "Understood."}]},
    ]
