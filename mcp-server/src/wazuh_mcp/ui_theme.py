"""Shared chrome for the OAuth pages and the investigation timeline.

Geist is vendored (SIL OFL 1.1, see fonts/OFL.txt) and embedded as a data URI so
the pages stay self-contained under ``default-src 'none'``. Callers that embed
``css()`` must allow ``font-src data:``.
"""

import base64
from functools import lru_cache
from pathlib import Path

_FONTS = Path(__file__).resolve().parent / "fonts"

# Cool neutral surfaces, one ink button, brand blue only on the focus ring.
# Spacing is a 4px grid. Radii are 0 on the page and 8px on controls.
_TOKENS = """
:root {
  color-scheme: light dark;
  --bg: #f3f4f6;
  --ink: #12141a;
  --muted: #3e4654;
  --line: #d5d8e0;
  --line-strong: #5c6578;
  --panel: #ffffff;
  --field: #f7f8fa;
  --focus: #1d4ed8;
  --warn: #7a4e00;
  --err: #9f1239;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0a0c10;
    --ink: #f3f5f9;
    --muted: #c5cbd6;
    --line: #262b39;
    --line-strong: #6d768b;
    --panel: #11141b;
    --field: #0c0e13;
    --focus: #93b4ff;
    --warn: #f0c14a;
    --err: #ffb4ab;
  }
}
* { box-sizing: border-box; }
html { font-family: Geist, ui-sans-serif, sans-serif; }
body {
  margin: 0;
  min-height: 100vh;
  background: var(--bg);
  color: var(--ink);
  font: 14px/1.5 Geist, ui-sans-serif, sans-serif;
}
.skip {
  position: absolute;
  left: 12px;
  top: 8px;
  padding: 8px 12px;
  background: var(--ink);
  color: var(--bg);
  transform: translateY(-150%);
}
.skip:focus { transform: none; }
.bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  min-height: 60px;
  padding: 0 20px;
  background: var(--panel);
  border-bottom: 1px solid var(--line);
  font-weight: 600;
}
.bar span { color: var(--muted); font-weight: 400; font-size: 12px; }
.sheet { max-width: 40rem; padding: 28px 20px 48px; }
h1 {
  margin: 0 0 8px;
  font-size: 22px;
  font-weight: 600;
  letter-spacing: -0.035em;
  line-height: 1.25;
  text-wrap: balance;
}
h2 {
  margin: 20px 0 0;
  font-size: 12px;
  font-weight: 600;
  letter-spacing: 0;
  text-transform: none;
}
p { margin: 0 0 12px; }
.lead { color: var(--muted); max-width: 38em; text-wrap: pretty; }
.facts { margin: 16px 0 0; }
.facts div, .access li {
  display: grid;
  grid-template-columns: 8.5rem 1fr;
  gap: 12px;
  padding: 10px 0;
  border-bottom: 1px solid var(--line);
}
.facts { border-top: 1px solid var(--line); }
dt, .access .name { color: var(--muted); font-size: 12px; }
dd { margin: 0; font-variant-numeric: tabular-nums; }
.access { list-style: none; padding: 0; margin: 8px 0 0; border-top: 1px solid var(--line); }
.access .name { font-family: ui-monospace, monospace; font-size: 13px; color: var(--ink); }
.access .write .note { color: var(--warn); }
label { display: block; margin: 20px 0 6px; font-size: 12px; font-weight: 600; }
input[type=password] {
  width: 100%;
  min-height: 40px;
  padding: 8px 12px;
  font: inherit;
  color: inherit;
  background: var(--field);
  border: 1px solid var(--line-strong);
  border-radius: 8px;
}
.alert { color: var(--err); font-weight: 600; margin: 8px 0 0; }
.actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 16px; }
button, .go {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 40px;
  padding: 8px 16px;
  font: inherit;
  font-weight: 600;
  text-decoration: none;
  border-radius: 8px;
  border: 1px solid var(--line-strong);
  background: transparent;
  color: var(--ink);
  cursor: pointer;
}
.primary { background: var(--ink); color: var(--bg); border-color: var(--ink); }
input:focus-visible, button:focus-visible, a:focus-visible {
  outline: 2px solid var(--focus);
  outline-offset: 2px;
}
@media (max-width: 640px) {
  .sheet { padding: 20px 16px 40px; }
  .bar { padding: 0 16px; }
  .facts div, .access li { grid-template-columns: 1fr; gap: 2px; }
}
@media (prefers-reduced-motion: reduce) {
  * { transition: none !important; animation: none !important; }
}
"""


@lru_cache(maxsize=1)
def css() -> str:
    faces = []
    for weight, filename in (("400", "Geist-Regular.woff2"), ("600", "Geist-SemiBold.woff2")):
        payload = base64.b64encode((_FONTS / filename).read_bytes()).decode()
        faces.append(
            "@font-face{"
            "font-family:Geist;font-style:normal;font-weight:" + weight + ";"
            "font-display:swap;"
            "src:url(data:font/woff2;base64," + payload + ") format('woff2');}"
        )
    return "\n".join(faces) + _TOKENS
