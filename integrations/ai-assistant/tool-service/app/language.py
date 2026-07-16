"""Deterministic bilingual language detection (V3.8a). No model."""
from __future__ import annotations

import re
import unicodedata

_ES_DIACRITICS = frozenset("ñáéíóúü¿¡")
_ES_STOP = frozenset(
    """
    que qué cual cuál cuales cuáles como cómo cuando cuándo donde dónde
    cuantos cuántos cuantas cuántas cuanto cuánto cuanta cuánta
    alertas agentes fallos reglas muestrame muéstrame ultima última ultimos
    últimos ultimas últimas semana dias días horas entre sin para con del
    los las una uno unos unas este esta estos estas
    """.split()
)
_EN_STOP = frozenset(
    """
    how many what which when where show give the last alerts agents failures
    rules week days hours between from for with
    """.split()
)


def _fold(text: str) -> str:
    text = text.casefold()
    return "".join(
        c for c in unicodedata.normalize("NFD", text) if unicodedata.category(c) != "Mn"
    )


def detect(text: str) -> str:
    """Return ``en`` or ``es`` for the user's message."""
    raw = (text or "").strip()
    if not raw:
        return "en"
    if any(c in raw for c in _ES_DIACRITICS):
        return "es"
    folded = _fold(raw)
    tokens = re.findall(r"[a-z0-9]+", folded)
    if not tokens:
        return "en"
    es_hits = sum(1 for t in tokens if t in _ES_STOP)
    en_hits = sum(1 for t in tokens if t in _EN_STOP)
    if es_hits >= 2 and es_hits > en_hits:
        return "es"
    return "en"


def language_name(lang: str) -> str:
    return "Spanish" if lang == "es" else "English"
