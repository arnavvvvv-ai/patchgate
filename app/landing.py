"""Landing hero for the PatchGate dashboard: a centred serif headline over a drifting peach glow, with four
floating "product artifact" cards around it (after the Steep reference). Every number is passed in from the
evaluation result files.

Rendering constraints (st.html sanitises its input):
  * no JavaScript and no <svg>, so the ring, the line chart and the cursors are drawn with CSS only;
  * a <style> block containing '<' followed by a letter is dropped, so @property syntax strings use the
    CSS escape '\\3C' for '<'. CSS holds rules only; the app wraps them in its single <style> block.

Animation inventory (all CSS, all disabled under prefers-reduced-motion):
  cards rise in, then float, and lift on hover · table bars grow · the line draws segment by segment ·
  the ring fills and its numbers count up · the composer types a patch and shows the gate's verdict ·
  avatar cursors drift · the background glow slowly moves.
"""
from __future__ import annotations

import math
from html import escape
from typing import Any

CSS = """
  @property --pg-n { syntax: '\\3C integer>'; inherits: false; initial-value: 0; }
  @property --pg-p { syntax: '\\3C percentage>'; inherits: false; initial-value: 0%; }
  @keyframes pg-rise  { from { opacity: 0; transform: translateY(28px); filter: blur(4px); } to { opacity: 1; transform: none; filter: none; } }
  @keyframes pg-float { 0%, 100% { translate: 0 0; } 50% { translate: 0 -10px; } }
  @keyframes pg-drift { 0% { transform: translate3d(-4%, -2%, 0) scale(1); } 100% { transform: translate3d(5%, 3%, 0) scale(1.12); } }
  @keyframes pg-grow  { from { transform: scaleX(0); } }
  @keyframes pg-seg   { from { scale: 0 1; } }
  @keyframes pg-pop   { from { opacity: 0; scale: .2; } }
  @keyframes pg-ring  { from { --pg-p: 0%; } to { --pg-p: var(--to); } }
  @keyframes pg-count { to { --pg-n: var(--to); } }
  @keyframes pg-pulse { 0% { box-shadow: 0 0 0 0 rgba(93,42,26,.45); } 70%, 100% { box-shadow: 0 0 0 9px rgba(93,42,26,0); } }
  @keyframes pg-type  { 0%, 6% { width: 0; } 42%, 88% { width: var(--chars); } 96%, 100% { width: 0; } }
  @keyframes pg-caret { 50% { border-color: transparent; } }
  @keyframes pg-verdict { 0%, 44% { opacity: 0; transform: translateY(6px) scale(.96); } 50%, 86% { opacity: 1; transform: none; } 94%, 100% { opacity: 0; } }
  @keyframes pg-cursor { 0%, 100% { translate: 0 0; } 50% { translate: 10px -8px; } }

  .st-key-hero {
    position: relative; isolation: isolate; overflow: hidden; container-type: inline-size;
    background: #ffffff; border-radius: 32px; min-height: 660px; padding-bottom: 32px;
  }
  .st-key-hero::before {
    content: ""; position: absolute; inset: -25%; z-index: -1; pointer-events: none; filter: blur(36px);
    background:
      radial-gradient(34% 38% at 60% 56%, rgba(249, 186, 150, .55), transparent 70%),
      radial-gradient(30% 34% at 40% 44%, rgba(251, 225, 209, .85), transparent 72%),
      radial-gradient(26% 30% at 72% 34%, rgba(244, 204, 214, .50), transparent 70%),
      radial-gradient(40% 40% at 50% 50%, rgba(250, 250, 251, .9), transparent 80%);
    animation: pg-drift 18s ease-in-out infinite alternate;
  }
  .pg-stage { position: relative; height: 640px; margin-bottom: -640px; pointer-events: none; z-index: 1; }
  .pg-head  { position: relative; z-index: 2; max-width: 720px; margin: 0 auto; padding-top: 128px; text-align: center; }
  .st-key-hero-cta { position: relative; z-index: 3; }

  .pg-pill { display: inline-flex; align-items: center; gap: 10px; padding: 7px 16px; border-radius: 9999px;
             background: rgba(255,255,255,.75); box-shadow: 0 0 0 1px rgba(4,23,43,.06); backdrop-filter: blur(6px);
             font: 450 14px/1 Inter, ui-sans-serif, system-ui, sans-serif; color: #17191c; animation: pg-rise .8s ease both; }
  .pg-dot { width: 7px; height: 7px; border-radius: 50%; background: #5d2a1a; animation: pg-pulse 2.2s infinite; }
  .pg-h1 { font-family: 'Source Serif 4', Georgia, serif; font-weight: 400; font-size: clamp(44px, 5.4cqw, 76px);
           line-height: 1.08; letter-spacing: -0.025em; color: #17191c; margin: 26px 0 0; animation: pg-rise .9s .08s ease both; }
  .pg-h1 em { font-style: italic; }
  .pg-sub { font: 400 18px/1.5 Inter, ui-sans-serif, system-ui, sans-serif; color: #3d4048; max-width: 560px;
            margin: 22px auto 0; animation: pg-rise .9s .16s ease both; }

  .pg-card { position: absolute; pointer-events: auto; background: #ffffff; border-radius: 20px; padding: 18px 20px 16px;
             font-family: Inter, ui-sans-serif, system-ui, sans-serif; color: #17191c;
             box-shadow: 0 0 0 1px rgba(4,23,43,.05), 0 20px 25px -5px rgba(0,0,0,.10), 0 8px 10px -6px rgba(0,0,0,.10);
             animation: pg-rise 1s var(--d, 0s) cubic-bezier(.2,.7,.2,1) both, pg-float 8s calc(var(--d, 0s) + 1s) ease-in-out infinite;
             transition: scale .35s cubic-bezier(.2,.7,.2,1), box-shadow .35s; }
  .pg-card:hover { scale: 1.035; box-shadow: 0 0 0 1px rgba(4,23,43,.06), 0 30px 45px -12px rgba(0,0,0,.18), 0 12px 18px -8px rgba(0,0,0,.12); }
  .pg-label { font-size: 13px; font-weight: 500; color: #17191c; }
  .pg-meta  { font-size: 12px; color: #777b86; margin-top: 2px; }
  .pg-big   { font-size: 30px; font-weight: 500; letter-spacing: -0.02em; line-height: 1; }

  .pg-table { width: 100%; margin-top: 12px; border-collapse: collapse; font-size: 13px; }
  .pg-table td { padding: 6px 0; border-top: 1px solid #f0f0f2; white-space: nowrap; }
  .pg-table td:last-child { text-align: right; font-variant-numeric: tabular-nums; width: 54px; }
  .pg-bar { height: 6px; border-radius: 9999px; background: #a3a6af; transform-origin: left; animation: pg-grow 1.2s var(--bd) cubic-bezier(.2,.7,.2,1) both; }
  .pg-row-gate td { color: #5d2a1a; font-weight: 500; }
  .pg-row-gate .pg-bar { background: #5d2a1a; min-width: 6px; }

  .pg-chart { position: relative; margin-top: 10px; }
  .pg-grid  { position: absolute; left: 0; right: 0; top: 50%; border-top: 1px dashed #ececee; }
  .pg-seg   { position: absolute; height: 2.4px; border-radius: 2px; background: #5d2a1a; transform-origin: 0 50%;
              animation: pg-seg .55s var(--sd) cubic-bezier(.4,0,.2,1) both; }
  .pg-pt    { position: absolute; width: 7px; height: 7px; margin: -3.5px 0 0 -3.5px; border-radius: 50%; background: #5d2a1a;
              box-shadow: 0 0 0 3px #fff; animation: pg-pop .35s var(--sd) ease both; }
  .pg-axis  { display: flex; justify-content: space-between; font-size: 11px; color: #a3a6af; margin-top: 6px; }

  .pg-ring-wrap { position: relative; width: 96px; height: 96px; margin: 14px 0 6px auto; }
  .pg-ring { position: absolute; inset: 0; border-radius: 50%; --pg-p: var(--to);
             background: conic-gradient(#5d2a1a var(--pg-p), #f2f2f3 0);
             -webkit-mask: radial-gradient(farthest-side, transparent calc(100% - 8px), #000 calc(100% - 7px));
             mask: radial-gradient(farthest-side, transparent calc(100% - 8px), #000 calc(100% - 7px));
             animation: pg-ring 1.8s .9s cubic-bezier(.4,0,.2,1) both; }
  .pg-ring-label { position: absolute; inset: 0; display: grid; place-items: center; text-align: center; }
  .pg-count { --pg-n: var(--to); animation: pg-count 1.8s .9s cubic-bezier(.2,.7,.2,1) both; counter-reset: n var(--pg-n); }
  .pg-count::after { content: counter(n); }
  .pg-count.pg-start { --pg-n: 0; }

  .pg-composer .pg-input { font: 13px/1.4 'JetBrains Mono', ui-monospace, monospace; color: #17191c; min-height: 20px; }
  .pg-type { display: inline-block; vertical-align: bottom; overflow: hidden; white-space: nowrap; width: 0;
             border-right: 2px solid #17191c; animation: pg-type 7s 1.4s steps(var(--steps)) infinite, pg-caret .8s step-end infinite; }
  .pg-composer-foot { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-top: 14px; }
  .pg-chip { display: inline-flex; align-items: center; gap: 6px; padding: 5px 11px; border-radius: 9999px; background: #fbe1d1;
             color: #5d2a1a; font-size: 12px; font-weight: 500; white-space: nowrap; opacity: 0; animation: pg-verdict 7s 1.4s infinite; }
  .pg-send { width: 34px; height: 34px; border-radius: 50%; background: #17191c; color: #fff; display: grid; place-items: center; font-size: 16px; }
  .pg-hint { font-size: 12px; color: #a3a6af; white-space: nowrap; }

  .pg-avatar { position: absolute; pointer-events: none; z-index: 2; animation: pg-rise 1s var(--d) ease both, pg-cursor 6s var(--d) ease-in-out infinite; }
  .pg-avatar span { display: grid; place-items: center; width: 40px; height: 40px; border-radius: 50%; font: 500 13px Inter, sans-serif; color: #17191c;
                    box-shadow: 0 0 0 2px #fff, 0 6px 14px -4px rgba(0,0,0,.2); }
  .pg-avatar i { position: absolute; width: 14px; height: 16px; background: #17191c;
                 clip-path: polygon(0 0, 100% 62%, 56% 66%, 38% 100%); filter: drop-shadow(0 1px 1px rgba(0,0,0,.3)); }

  @container (max-width: 1080px) { .pg-card, .pg-avatar { display: none; } .pg-head { padding-top: 72px; } .st-key-hero { min-height: 0; } .pg-stage { height: 0; margin-bottom: 0; } }
  @media (prefers-reduced-motion: reduce) {
    .st-key-hero::before, .pg-card, .pg-avatar, .pg-pill, .pg-h1, .pg-sub, .pg-bar, .pg-seg, .pg-pt, .pg-ring, .pg-count, .pg-chip, .pg-dot, .pg-type { animation: none !important; }
    .pg-type { width: var(--chars); border-right: none; } .pg-chip { opacity: 1; } .pg-count.pg-start { --pg-n: var(--to); }
  }

  /* Overview cards lift slightly under the pointer. */
  [class*="st-key-artifact-step"], [class*="st-key-artifact-check"], [class*="st-key-card-base"] { transition: translate .3s cubic-bezier(.2,.7,.2,1), box-shadow .3s; }
  [class*="st-key-artifact-step"]:hover, [class*="st-key-artifact-check"]:hover, [class*="st-key-card-base"]:hover { translate: 0 -4px; }

  /* Gentle entrance for the dashboard panels below the hero. */
  [class*="st-key-artifact"], [class*="st-key-card"], .st-key-peach { animation: pg-rise .6s cubic-bezier(.2,.7,.2,1) both; }
  @media (prefers-reduced-motion: reduce) { [class*="st-key-artifact"], [class*="st-key-card"], .st-key-peach { animation: none; } }
"""


def _pct(x: float) -> str:
    return f"{x * 100:.1f}%".replace(".0%", "%")


def _table_card(gates: list[tuple[str, float]], total: int) -> str:
    rows = []
    for i, (label, rate) in enumerate(gates):
        cls = ' class="pg-row-gate"' if label == "PatchGate" else ""
        rows.append(
            f'<tr{cls}><td style="width:104px">{escape(label)}</td>'
            f'<td><div class="pg-bar" style="width:{max(rate * 100, 0):.1f}%;--bd:{0.7 + i * 0.12:.2f}s"></div></td>'
            f'<td>{_pct(rate)}</td></tr>'
        )
    return (f'<div class="pg-card" style="left:-6px;top:64px;width:300px;--d:.25s" role="img" '
            f'aria-label="False-accept rate by gate">'
            f'<div class="pg-label">False accepts by gate</div>'
            f'<div class="pg-meta">{total:,} harmful patches · held-out benchmark</div>'
            f'<table class="pg-table">{"".join(rows)}</table></div>')


def _line_card(series: list[float], labels: list[str]) -> str:
    """A line chart built from rotated divs: each segment grows after the previous one (CSS only)."""
    w, h, pad = 224.0, 70.0, 6.0
    step = (w - 2 * pad) / max(len(series) - 1, 1)
    pts = [(pad + i * step, pad + (1 - v) * (h - 2 * pad)) for i, v in enumerate(series)]
    parts = ['<div class="pg-grid"></div>']
    for i in range(len(pts) - 1):
        (x1, y1), (x2, y2) = pts[i], pts[i + 1]
        length = math.dist(pts[i], pts[i + 1])
        angle = math.degrees(math.atan2(y2 - y1, x2 - x1))
        parts.append(f'<div class="pg-seg" style="left:{x1:.1f}px;top:{y1 - 1.2:.1f}px;width:{length:.1f}px;'
                     f'transform:rotate({angle:.2f}deg);--sd:{1.1 + i * 0.5:.2f}s"></div>')
    for i, (x, y) in enumerate(pts):
        parts.append(f'<div class="pg-pt" style="left:{x:.1f}px;top:{y:.1f}px;--sd:{1.0 + i * 0.5:.2f}s"></div>')
    return (f'<div class="pg-card" style="left:5%;bottom:28px;width:268px;--d:.55s">'
            f'<div class="pg-label">Adding checks</div><div class="pg-meta">False accepts as each gate adds checks</div>'
            f'<div class="pg-chart" style="width:{w:.0f}px;height:{h:.0f}px" role="img" '
            f'aria-label="False-accept rate falls from {_pct(series[0])} to {_pct(series[-1])} as checks are added">{"".join(parts)}</div>'
            f'<div class="pg-axis" style="width:{w:.0f}px">{"".join(f"<span>{escape(lb)}</span>" for lb in labels)}</div>'
            f'<div style="display:flex;align-items:baseline;gap:8px;margin-top:10px">'
            f'<div class="pg-big">{_pct(series[-1])}</div><div class="pg-meta">harmful accepted, all six checks</div></div></div>')


def _ring_card(correct: int, total: int, misses: int) -> str:
    p = round(100 * correct / total) if total else 0
    return (f'<div class="pg-card" style="right:-6px;top:196px;width:236px;--d:.4s">'
            f'<div class="pg-label">Challenge set</div><div class="pg-meta">{total} cases written to break the gate</div>'
            f'<div class="pg-ring-wrap" role="img" aria-label="{correct} of {total} judged correctly">'
            f'<div class="pg-ring" style="--to:{p}%"></div>'
            f'<div class="pg-ring-label"><div><div style="font-size:20px;font-weight:500">'
            f'<span class="pg-count pg-start" style="--to:{p}"></span>%</div>'
            f'<div class="pg-meta" style="margin:0">correct</div></div></div></div>'
            f'<div class="pg-big" style="font-size:22px"><span class="pg-count pg-start" style="--to:{correct}"></span> / {total}</div>'
            f'<div class="pg-meta">{misses} runtime-only breakages still pass</div></div>')


def _composer_card(path: str) -> str:
    text = f"replace {path}"
    return (f'<div class="pg-card pg-composer" style="left:calc(50% + 30px);bottom:22px;width:380px;--d:.7s">'
            f'<div class="pg-input"><span class="pg-type" style="--chars:{len(text)}ch;--steps:{len(text)}">{escape(text)}</span></div>'
            f'<div class="pg-composer-foot"><span class="pg-chip">✕ Rejected · scope</span>'
            f'<span style="display:flex;align-items:center;gap:10px"><span class="pg-hint">Verify any patch</span>'
            f'<span class="pg-send" aria-hidden="true">↑</span></span></div></div>')


def _avatar(initials: str, name: str, tint: str, style: str, delay: str, cursor_style: str) -> str:
    return (f'<div class="pg-avatar" style="{style};--d:{delay}" title="{escape(name)}">'
            f'<span style="background:{tint}">{escape(initials)}</span><i style="{cursor_style}"></i></div>')


def hero_html(bench: dict[str, Any] | None, challenge: dict[str, Any] | None) -> str:
    """The stage of floating cards plus the centred headline. Cards whose data file is missing are omitted."""
    cards: list[str] = []
    if bench:
        m = bench["metrics"]
        order = [("Patch applies", "apply-only"), ("Re-lint target", "relint-target"),
                 ("Re-lint all", "relint-full"), ("PatchGate", "patchgate")]
        gates = [(label, m[k]["false_accept_rate"]) for label, k in order if k in m]
        cards.append(_table_card(gates, m["patchgate"]["invalid_total"]))
        cards.append(_line_card([rate for _, rate in gates], ["Apply", "Target", "All", "Gate"][: len(gates)]))
    if challenge:
        s = challenge["summary"]["patchgate"]
        total = s["invalid"] + s["valid"]
        cards.append(_ring_card(total - s["false_accepts"] - s["false_rejects"], total, s["false_accepts"]))
    cards.append(_composer_card("…/containers/0/securityContext"))
    cards.append(_avatar("G", "Gemini proposes", "#d8eedf", "left:calc(5% - 34px);bottom:118px", "1.2s",
                         "left:34px;top:-6px;transform:scaleX(-1)"))
    cards.append(_avatar("PG", "PatchGate verifies", "#dbe6f7", "left:calc(50% + 250px);bottom:-6px", "1.5s",
                         "left:-8px;top:-8px"))
    head = (
        '<div class="pg-head">'
        '<span class="pg-pill"><span class="pg-dot"></span>Gemini proposes · PatchGate verifies</span>'
        '<h1 class="pg-h1">Repairs you can verify,<br><em>not just re-lint</em></h1>'
        '<p class="pg-sub">Gemini suggests a patch for each misconfiguration. PatchGate accepts it only when the '
        'problem is gone and nothing else about the workload changed.</p>'
        '</div>'
    )
    return f'<div class="pg-stage">{"".join(cards)}</div>{head}'
