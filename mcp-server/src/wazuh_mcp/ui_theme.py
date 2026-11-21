"""Shared chrome for the OAuth pages, the timeline viewer, and the mock IdP.

Potocolom's studio type is Geist at 14px with 12px labels and a 22px title.
That scale is not used here. Text is Source Sans 3 (humanist, OFL, Adobe,
reserved name "Source"). Identifiers, scopes, and timestamps are Source Code
Pro (OFL, Adobe, same reserved name). Both are vendored as latin woff2 and
embedded as data URIs. Callers that embed ``css()`` must allow ``font-src data:``.

Licences: fonts/OFL-SourceSans3.txt and fonts/OFL-SourceCodePro.txt.
"""

import base64
import html
from functools import lru_cache
from pathlib import Path

_FONTS = Path(__file__).resolve().parent / "fonts"

# 16 / 20 / 32. Labels match the body size and use weight, not a smaller grey.
# Two sans weights only. Mono is reserved for names, scopes, and times.
_TOKENS = """
:root {
  color-scheme: light dark;
  --bg: #f4f1ea;
  --ink: #1c1915;
  --muted: #3f3a33;
  --line: #d9d2c5;
  --line-strong: #6f675c;
  --panel: #fbf9f4;
  --field: #fffdf8;
  --focus: #1d4e89;
  --warn: #6b3e08;
  --err: #8f1d2c;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #141210;
    --ink: #f3efe6;
    --muted: #d2cbbd;
    --line: #3a342c;
    --line-strong: #8a8174;
    --panel: #1c1916;
    --field: #100e0c;
    --focus: #9ec1ea;
    --warn: #f0c14a;
    --err: #ffb4ab;
  }
}
* { box-sizing: border-box; }
html { font-family: "Source Sans 3", "Segoe UI", sans-serif; }
body {
  margin: 0;
  min-height: 100vh;
  background: var(--bg);
  color: var(--ink);
  font: 400 16px/1.5 "Source Sans 3", "Segoe UI", sans-serif;
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
  align-items: baseline;
  justify-content: space-between;
  gap: 16px;
  min-height: 64px;
  padding: 0 28px;
  background: var(--panel);
  border-bottom: 1px solid var(--line);
}
.wordmark { margin: 0; font-size: 20px; font-weight: 600; letter-spacing: -0.02em; line-height: 1; }
.wordmark-mark {
  margin-left: 0.55em;
  font-family: "Source Code Pro", ui-monospace, monospace;
  font-size: 0.72em;
  font-weight: 400;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}
.bar-context { margin: 0; color: var(--muted); font-size: 16px; font-weight: 400; }
.sheet { max-width: 38rem; margin: 0 auto; padding: 40px 28px 64px; }
.split-page {
  display: grid;
  grid-template-columns: minmax(0, 1.15fr) minmax(18rem, 26rem);
  gap: 48px;
  align-items: start;
  max-width: 68rem;
  margin: 0 auto;
  padding: 40px 40px 72px;
}
h1 {
  margin: 0 0 12px;
  font-size: 32px;
  font-weight: 600;
  letter-spacing: -0.02em;
  line-height: 1.15;
  text-wrap: balance;
}
h2 {
  margin: 28px 0 8px;
  font-size: 20px;
  font-weight: 600;
  letter-spacing: 0;
  line-height: 1.3;
}
p { margin: 0 0 12px; }
.lead { max-width: 62ch; text-wrap: pretty; }
.facts { margin: 20px 0 0; }
.facts div, .access li {
  display: grid;
  grid-template-columns: 9rem 1fr;
  gap: 16px;
  align-items: baseline;
  padding: 12px 0;
  border-bottom: 1px solid var(--line);
}
.facts { border-top: 1px solid var(--line); }
dt { font-size: 16px; font-weight: 600; }
dd { margin: 0; }
.mono, time, .access .name, dd {
  font-family: "Source Code Pro", ui-monospace, monospace;
  font-size: 15px;
  font-weight: 400;
  font-variant-numeric: tabular-nums;
  letter-spacing: 0;
}
.access { list-style: none; padding: 0; margin: 8px 0 0; border-top: 1px solid var(--line); }
.access .name { color: var(--ink); }
.access .note { font-family: "Source Sans 3", "Segoe UI", sans-serif; font-size: 16px; }
.access .write .note { color: var(--warn); }
.form-pane {
  padding: 24px 0 0;
  border-top: 1px solid var(--line);
}
label { display: block; margin: 0 0 8px; font-size: 16px; font-weight: 600; }
input[type=password], input[type=email] {
  width: 100%;
  min-height: 44px;
  padding: 8px 12px;
  font: 16px/1.4 "Source Code Pro", ui-monospace, monospace;
  color: inherit;
  background: var(--field);
  border: 1px solid var(--line-strong);
  border-radius: 2px;
}
.alert { color: var(--err); font-weight: 600; margin: 12px 0 0; }
.actions { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 20px; }
button, .go {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 44px;
  padding: 8px 18px;
  font: 600 16px/1 "Source Sans 3", "Segoe UI", sans-serif;
  text-decoration: none;
  border-radius: 2px;
  border: 1px solid var(--line-strong);
  background: transparent;
  color: var(--ink);
  cursor: pointer;
}
.primary { background: var(--ink); color: var(--bg); border-color: var(--ink); }
input:focus-visible, button:focus-visible, a:focus-visible {
  outline: 2px solid var(--focus);
  outline-offset: 3px;
}
@media (max-width: 800px) {
  .bar { padding: 0 16px; }
  .sheet, .split-page { padding: 24px 16px 48px; }
  .split-page { grid-template-columns: 1fr; gap: 8px; }
  .facts div, .access li { grid-template-columns: 1fr; gap: 2px; }
  h1 { font-size: 28px; }
}
@media (min-width: 801px) {
  .form-pane { padding: 0 0 0 40px; border-top: 0; border-left: 1px solid var(--line); }
}
@media (prefers-reduced-motion: reduce) {
  * { transition: none !important; animation: none !important; }
}
"""


def bar(context: str) -> str:
    """Wordmark plus a plain context label. No mark, no icon."""
    return (
        '<header class="bar"><p class="wordmark">'
        '<span class="wordmark-name">Wazuh</span>'
        '<span class="wordmark-mark">MCP</span></p>'
        f'<p class="bar-context">{html.escape(context)}</p></header>'
    )


@lru_cache(maxsize=1)
def css() -> str:
    faces = []
    for family, weight, filename in (
        ("Source Sans 3", "400", "SourceSans3-400.woff2"),
        ("Source Sans 3", "600", "SourceSans3-600.woff2"),
        ("Source Code Pro", "400", "SourceCodePro-400.woff2"),
    ):
        payload = base64.b64encode((_FONTS / filename).read_bytes()).decode()
        faces.append(
            "@font-face{"
            f"font-family:'{family}';font-style:normal;font-weight:{weight};"
            "font-display:swap;"
            f"src:url(data:font/woff2;base64,{payload}) format('woff2');"
            "}"
        )
    return "\n".join(faces) + _TOKENS
