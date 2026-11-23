"""Shared chrome for the OAuth pages, the timeline viewer, and the mock IdP.

The design system is the AI SOC console's, so the two products read as one:
Geist at 14/21 for body text, weights 400, 500 and 600 only, and no monospace
anywhere (identifiers sit in ID chips, numbers use tabular figures).

Geist (Vercel, SIL Open Font License 1.1) is vendored as latin-subset woff2
and embedded as data URIs, so nothing is fetched. Callers that embed ``css()``
must allow ``font-src data:``. Licence: fonts/OFL-Geist.txt.

Icons are inline SVG (stroke 1.75, currentColor, aria-hidden). Light and dark
follow ``prefers-color-scheme`` because the host decides.
"""

import base64
import html
from functools import lru_cache
from pathlib import Path

_FONTS = Path(__file__).resolve().parent / "fonts"

_TOKENS = """
:root {
  color-scheme: light dark;
  --bg: #fafaf9; --panel: #ffffff; --panel-2: #f6f6f5; --hover: #f3f3f1;
  --ink: #1b1b1b; --ink-2: #5f5f5c; --muted: #6b6b68;
  --line: #e8e8e6; --line-strong: #d6d6d2; --field: #ffffff;
  --accent: #075bff; --accent-hover: #0049d6; --accent-subtle: #eef3ff; --on-accent: #ffffff;
  --focus: #075bff;
  --ok: #006045; --ok-subtle: #ebfdf1; --ok-mark: #009966;
  --warn: #bb4d00; --warn-subtle: #fffaea; --warn-line: #fde7a8; --warn-mark: #ffac00;
  --err: #c10007; --err-subtle: #fff3f3; --err-mark: #e7000b;
  --info: #193cb8; --info-subtle: #eff6ff; --info-mark: #00a6f4;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0e0f10; --panel: #161718; --panel-2: #1c1d1f; --hover: #222326;
    --ink: #ededec; --ink-2: #a6a6a3; --muted: #8b8b88;
    --line: #26282a; --line-strong: #36383c; --field: #161718;
    --accent: #5b95ff; --accent-hover: #7aa9ff; --accent-subtle: #14203a; --on-accent: #0b0c0d;
    --focus: #7aa9ff;
    --ok: #a4f4cf; --ok-subtle: #14231c; --ok-mark: #00d492;
    --warn: #ff8904; --warn-subtle: #2e210f; --warn-line: #4d3817; --warn-mark: #ffac00;
    --err: #ff6467; --err-subtle: #2c1314; --err-mark: #fb2c36;
    --info: #51a2ff; --info-subtle: #171f32; --info-mark: #00a6f4;
  }
}
* { box-sizing: border-box; }
html, body, input, button { font-family: "Geist", ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif; }
body { margin: 0; min-height: 100vh; background: var(--bg); color: var(--ink); font: 400 14px/21px "Geist", ui-sans-serif, system-ui, sans-serif; }
.num, time, dd { font-variant-numeric: tabular-nums; }
svg { flex: none; }
.skip { position: absolute; left: 12px; top: 8px; padding: 8px 12px; background: var(--accent); color: var(--on-accent); border-radius: 8px; transform: translateY(-150%); }
.skip:focus { transform: none; }

.bar { display: flex; align-items: center; gap: 10px; height: 56px; padding: 0 24px; background: var(--panel); border-bottom: 1px solid var(--line); }
.bar .mark { color: var(--accent); display: inline-flex; }
.wordmark { margin: 0; font-size: 15px; font-weight: 600; line-height: 1; }
.bar-divider { color: var(--line-strong); }
.bar-context { margin: 0; color: var(--ink-2); }
.bar-host { margin: 0 0 0 auto; display: inline-flex; align-items: center; gap: 8px; color: var(--ink-2); font-size: 13px; }
.bar-host::before { content: ""; width: 8px; height: 8px; border-radius: 50%; background: var(--ok-mark); }

h1 { margin: 0 0 8px; font-size: 28px; line-height: 34px; font-weight: 600; letter-spacing: -0.01em; text-wrap: balance; }
h2 { margin: 24px 0 8px; font-size: 16px; line-height: 24px; font-weight: 600; }
p { margin: 0 0 12px; }
.lead { max-width: 62ch; color: var(--ink-2); text-wrap: pretty; }
.eyebrow { margin: 0 0 8px; color: var(--accent); font-size: 13px; line-height: 18px; font-weight: 500; }
.secondary, .hint { color: var(--muted); font-size: 12px; line-height: 18px; }

.tag { display: inline-flex; align-items: center; gap: 6px; height: 20px; padding: 0 6px; border-radius: 4px; font-size: 11px; line-height: 16px; font-weight: 500; white-space: nowrap; background: var(--panel-2); color: var(--ink-2); }
.tag::before { content: ""; width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
.tag.ok { background: var(--ok-subtle); color: var(--ok); }
.tag.ok::before { background: var(--ok-mark); }
.tag.warn { background: var(--warn-subtle); color: var(--warn); }
.tag.warn::before { background: var(--warn-mark); }
.tag.err { background: var(--err-subtle); color: var(--err); }
.tag.err::before { background: var(--err-mark); }
.tag.info { background: var(--info-subtle); color: var(--info); }
.tag.info::before { background: var(--info-mark); }
.chip { display: inline-flex; align-items: center; padding: 0 6px; border-radius: 4px; background: var(--panel-2); border: 1px solid var(--line); font-size: 12px; line-height: 18px; font-weight: 500; overflow-wrap: anywhere; }
.chip .pre { color: var(--muted); }

.facts { margin: 20px 0 0; }
.facts div { display: grid; grid-template-columns: 9rem 1fr; gap: 16px; align-items: baseline; padding: 10px 0; border-top: 1px solid var(--line); }
dt { color: var(--muted); font-size: 13px; line-height: 18px; font-weight: 500; }
dd { margin: 0; overflow-wrap: anywhere; }

.card { padding: 16px; background: var(--panel); border: 1px solid var(--line); border-radius: 10px; }
.card.warn { background: var(--warn-subtle); border-color: var(--warn-line); }

label { display: block; margin: 0 0 6px; font-size: 13px; line-height: 18px; font-weight: 500; }
input[type=password], input[type=text], input[type=email] {
  width: 100%; min-height: 36px; padding: 0 12px; font-size: 14px; color: inherit;
  background: var(--field); border: 1px solid var(--line-strong); border-radius: 8px;
}
input[aria-invalid=true] { border-color: var(--err); }
.alert { margin: 6px 0 0; color: var(--err); font-size: 13px; line-height: 18px; font-weight: 500; }
.actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 20px; }
button, .go {
  display: inline-flex; align-items: center; justify-content: center; gap: 6px;
  min-height: 36px; padding: 0 14px; font-size: 14px; line-height: 1; font-weight: 500;
  text-decoration: none; cursor: pointer; border-radius: 8px;
  background: var(--panel); color: var(--ink); border: 1px solid var(--line-strong);
  box-shadow: 0 1px 2px rgb(0 0 0 / 4%);
}
button:hover, .go:hover { background: var(--hover); }
.primary { background: var(--accent); color: var(--on-accent); border-color: var(--accent); box-shadow: none; }
.primary:hover { background: var(--accent-hover); border-color: var(--accent-hover); }
input:focus-visible, button:focus-visible, a:focus-visible, [tabindex]:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }

.sheet { max-width: 30rem; margin: 0 auto; padding: 48px 16px 64px; }
.sheet h1 { font-size: 20px; line-height: 28px; }
.tile { display: inline-flex; align-items: center; justify-content: center; width: 40px; height: 40px; margin-bottom: 16px; border-radius: 10px; background: var(--panel-2); color: var(--ink-2); }
.tile.ok { background: var(--ok-subtle); color: var(--ok); }
.tile.warn { background: var(--warn-subtle); color: var(--warn); }
.tile.err { background: var(--err-subtle); color: var(--err); }

.split-page { display: grid; grid-template-columns: minmax(0, 1fr) minmax(20rem, 24rem); gap: 48px; align-items: start; max-width: 64rem; margin: 0 auto; padding: 48px 24px 72px; }
.scopes { display: grid; gap: 8px; list-style: none; padding: 0; margin: 0; }
.scopes li { display: grid; grid-template-columns: 20px 1fr; gap: 12px; }
.scopes .icon { color: var(--ink-2); padding-top: 1px; }
.scopes li.warn .icon { color: var(--warn); }
.scopes .head { color: var(--ink); display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin: 0 0 2px; font-weight: 500; }
.scopes p { margin: 0; color: var(--ink-2); }
.form-pane { padding: 24px; background: var(--panel); border: 1px solid var(--line); border-radius: 12px; }
.form-pane h2 { margin-top: 0; }
.form-pane input, .form-pane button { min-height: 44px; }
.form-pane .actions { flex-direction: column; }
.reveal { display: flex; gap: 8px; }
.reveal button { flex: none; }
@media (max-width: 800px) {
  .bar { padding: 0 16px; }
  .split-page { grid-template-columns: 1fr; gap: 24px; padding: 24px 16px 48px; }
  .facts div { grid-template-columns: 1fr; gap: 2px; }
  input, button, .go { min-height: 44px; }
}
@media (prefers-reduced-motion: reduce) {
  * { transition: none !important; animation: none !important; }
}
"""

_PATHS = {
    "shield": '<path d="M12 3 4 6v6c0 4.5 3.4 8.3 8 9 4.6-.7 8-4.5 8-9V6z"/>',
    "eye": '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
    "bolt": '<path d="M13 2 4 14h7l-1 8 9-12h-7z"/>',
    "check": '<path d="m5 12 5 5L20 7"/>',
    "x": '<path d="M6 6l12 12M18 6 6 18"/>',
    "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    "alert": '<path d="M12 3 2 20h20z"/><path d="M12 10v4M12 17h.01"/>',
}


def icon(name: str, size: int = 16) -> str:
    """Inline SVG icon from the shared set. Decorative, so hidden from assistive tech."""
    return (
        f'<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
        f'stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{_PATHS[name]}</svg>'
    )


def bar(context: str, host: str = "") -> str:
    """Shield, "Wazuh MCP", a divider and the context. The server host sits on the right."""
    right = f'<p class="bar-host">{html.escape(host)}</p>' if host else ""
    return (
        f'<header class="bar"><span class="mark">{icon("shield", 20)}</span>'
        '<p class="wordmark">Wazuh MCP</p><span class="bar-divider" aria-hidden="true">/</span>'
        f'<p class="bar-context">{html.escape(context)}</p>{right}</header>'
    )


@lru_cache(maxsize=1)
def css() -> str:
    faces = []
    for weight in ("400", "500", "600"):
        payload = base64.b64encode((_FONTS / f"Geist-{weight}.woff2").read_bytes()).decode()
        faces.append(
            "@font-face{"
            f"font-family:'Geist';font-style:normal;font-weight:{weight};font-display:swap;"
            f"src:url(data:font/woff2;base64,{payload}) format('woff2');"
            "}"
        )
    return "\n".join(faces) + _TOKENS
