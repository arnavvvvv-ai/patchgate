"""PatchGate demo UI.   Run from the project root:  streamlit run app/streamlit_app.py

Visual language: serif headlines on white paper, mist-gray cards, floating white "artifacts" for the
interactive panels, and a single peach callout per view (theme in .streamlit/config.toml).
"""
from __future__ import annotations

import difflib
import json
import sys
from pathlib import Path
from typing import Any

import altair as alt
import pandas as pd
import streamlit as st

from patchgate.checks import CONTROLS, Finding, scan
from patchgate.config import ConfigError, load_settings
from patchgate.fixers import template_fix
from patchgate.llm import make_proposer
from patchgate.manifest import ManifestError, get_at, load_manifest
from patchgate.patch import PatchError, apply_patch, parse_patch
from patchgate.repair import repair_manifest
from patchgate.store import AuditStore
from patchgate.verifier import GATES, verify

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
RESULTS = ROOT / "evaluation" / "results"
sys.path.insert(0, str(Path(__file__).resolve().parent))
from landing import CSS as LANDING_CSS, hero_html  # noqa: E402  (sibling module of this script)

DEFAULT_EXAMPLE = "web-app.yaml"
BASELINES = ["apply-only", "relint-target", "relint-full", "patchgate"]
GATE_LABELS = {
    "apply-only": "Patch applies",
    "relint-target": "Re-lint target",
    "relint-full": "Re-lint all findings",
    "patchgate": "PatchGate",
    "patchgate-no-structural": "PatchGate − structural",
    "patchgate-no-scope": "PatchGate − scope",
    "patchgate-no-invariants": "PatchGate − invariants",
}
PROPOSER_HELP = {
    "simulated": "Replays hand-written candidates, some deliberately wrong. No Gemini call is made.",
    "template": "Deterministic rule-based fixes, like `kubescape fix`. No Gemini call is made.",
    "gemini": "Live Gemini proposals. Every patch still has to pass the gate.",
}
STATUS_ICON = {"repaired": ":material/check_circle:", "manual": ":material/person:",
               "unrepaired": ":material/error:", "resolved-by-other": ":material/subdirectory_arrow_right:"}
STATUS_LABEL = {"repaired": "Repaired", "manual": "Needs a human", "unrepaired": "Not repaired",
                "resolved-by-other": "Resolved by another fix"}
VIEWS = {"overview": ":material/home: Overview", "repair": ":material/build: Repair", "gate": ":material/shield: Gate playground",
         "evaluation": ":material/monitoring: Evaluation", "audit": ":material/history: Audit log"}

st.set_page_config(page_title="PatchGate", page_icon=":material/verified_user:", layout="wide")
settings = load_settings()

# Widget defaults live in Session State (never also as default=/value=, which Streamlit warns about), and are
# re-assigned each run so values survive while their view is hidden.
for _k, _v in {"view": "overview", "source": "Example", "example": DEFAULT_EXAMPLE, "pasted": "",
               "proposer": "simulated", "attempts": settings.max_attempts, "fallback": True,
               "gate_start": "template"}.items():
    if _k not in st.session_state:
        st.session_state[_k] = _v
for _k in ("view", "source", "example", "pasted", "proposer", "attempts", "fallback", "gate_finding", "gate_start"):
    if _k in st.session_state:
        st.session_state[_k] = st.session_state[_k]

# Styling the design system needs beyond config.toml; scoped to keyed containers only.
st.html("""
<style>
  [class*="st-key-artifact"] {
    background: #ffffff; border-radius: 20px; padding: 24px 24px 20px 24px;
    box-shadow: 0 0 0 1px rgba(4,23,43,0.05), 0 20px 25px -5px rgba(0,0,0,0.08), 0 8px 10px -6px rgba(0,0,0,0.08);
  }
  [class*="st-key-card"] { background: #f2f2f3; border-radius: 24px; padding: 24px; }
  [class*="st-key-card"] [data-testid="stMetric"] { background: #ffffff; }
  .st-key-peach { background: #fbe1d1; border-radius: 24px; padding: 40px 44px; }
  .st-key-peach, .st-key-peach p, .st-key-peach h2, .st-key-peach h3, .st-key-peach [data-testid="stCaptionContainer"] { color: #5d2a1a; }
  [class*="st-key-artifact"] h3, [class*="st-key-card"] h3, .st-key-peach h2 { letter-spacing: -0.015em; }
  [class*="st-key-eyebrow"] p, .st-key-peach-eyebrow p { letter-spacing: 0.12em; font-size: 13px; }
""" + LANDING_CSS + """
</style>
""")


# ---------------------------------------------------------------- data helpers

@st.cache_data(ttl="10m", max_entries=32)
def read_json(path: str, mtime: float) -> dict[str, Any]:
    """Cached JSON read; the file's mtime is part of the key so regenerated results show up."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def result(name: str) -> dict[str, Any] | None:
    p = RESULTS / name
    return read_json(str(p), p.stat().st_mtime) if p.exists() else None


def pct(x: float | None) -> str:
    return "—" if x is None else f"{x * 100:.1f}%".replace(".0%", "%")


def overbroad_example(res: dict[str, Any], f: Finding) -> list[dict[str, Any]] | None:
    """A realistic bad patch for the demo: rewrite the whole securityContext with only the fixed keys.

    Returned only when that rewrite would silently delete other existing settings.
    """
    cp = f.container_pointer
    tmpl = template_fix(res, f)
    if not cp or not tmpl:
        return None
    try:
        after = apply_patch(res, parse_patch(tmpl))
    except PatchError:
        return None
    old_sc = (get_at(res, cp) or {}).get("securityContext")
    new_sc = (get_at(after, cp) or {}).get("securityContext")
    if not isinstance(old_sc, dict) or not isinstance(new_sc, dict):
        return None
    changed = {k: v for k, v in new_sc.items() if old_sc.get(k) != v}
    if not changed or not set(old_sc) - set(changed):
        return None
    return [{"op": "replace", "path": f"{cp}/securityContext", "value": changed}]


def eyebrow(text: str, key: str | None = None) -> None:
    key = key or "eyebrow-" + "".join(ch if ch.isalnum() else "-" for ch in text.lower())
    with st.container(key=key):
        st.caption(text.upper())


# ---------------------------------------------------------------- nav and overview

bench = result("test_seed2026_summary.json")
challenge = result("challenge_set.json")
live = result("live_gemini_combined.json")


def go(target: str) -> None:
    st.session_state["view"] = target


with st.container(horizontal=True, vertical_alignment="center", key="nav"):
    st.markdown("**:material/verified_user: PatchGate**")
    st.space("stretch")
    view = st.segmented_control("View", list(VIEWS), format_func=VIEWS.get, required=True,
                                key="view", label_visibility="collapsed", wrap=True)
    st.space("stretch")
    if settings.gemini_configured:
        st.badge(f"Gemini · {settings.gemini_model}", icon=":material/bolt:", color="green")
    else:
        st.badge("Offline mode", icon=":material/cloud_off:", color="gray",
                 help="Set GEMINI_API_KEY in .env to enable live Gemini repairs.")


def render_overview() -> None:
    with st.container(key="hero"):
        st.html(hero_html(bench, challenge))
        with st.container(horizontal=True, horizontal_alignment="center", key="hero-cta"):
            st.button("Repair a manifest", type="primary", icon=":material/auto_fix_high:",
                      on_click=go, args=("repair",), key="cta_repair")
            st.button("Try the gate", icon=":material/shield:", on_click=go, args=("gate",), key="cta_gate")

    st.space("large")
    eyebrow("How it works")
    st.header("Three steps, one decision")
    steps = [
        (":material/search:", "01 · Scan", "Eleven controls from the Pod Security Standards find what is unsafe: "
         "root users, privileged mode, missing limits, host access."),
        (":material/auto_awesome:", "02 · Propose", "Gemini writes a small JSON Patch for one finding at a time. "
         "Secrets are masked before anything is sent."),
        (":material/verified_user:", "03 · Verify", "Six deterministic checks decide. Rejected patches go back to "
         "Gemini with the exact reasons; behaviour-changing fixes go to a human."),
    ]
    for col, (icon, title, body) in zip(st.columns(3, gap="medium"), steps):
        with col, st.container(key=f"artifact-step-{title[:2]}", height="stretch"):
            st.markdown(f"### {icon}")
            st.subheader(title)
            st.markdown(body)

    st.space("large")
    eyebrow("The gate")
    st.header("Six checks — three of them are new")
    ablation = {}
    if bench:
        m = bench["metrics"]
        ablation = {"structural": m.get("patchgate-no-structural"), "scope": m.get("patchgate-no-scope"),
                    "invariants": m.get("patchgate-no-invariants")}
    baseline = [("Applies", "The patch can be applied to the file at all."),
                ("Target fixed", "The finding it was meant to fix is gone."),
                ("No new findings", "It did not create another problem.")]
    added = [("structural", "Structural", "No new schema or type errors, such as \"false\" written as text or invented fields."),
             ("scope", "Scope", "Only the paths in this control's repair contract were touched."),
             ("invariants", "Invariants", "Identity, labels, images, ports, env and existing volumes are unchanged; limits ≥ requests.")]
    for col, (title, body) in zip(st.columns(3, gap="medium"), baseline):
        with col, st.container(key=f"card-base-{title[:3].lower()}", height="stretch"):
            st.caption("RE-LINT ALREADY DOES THIS")
            st.subheader(title)
            st.markdown(body)
    for col, (k, title, body) in zip(st.columns(3, gap="medium"), added):
        with col, st.container(key=f"artifact-check-{k}", height="stretch"):
            st.caption("ADDED BY PATCHGATE")
            st.subheader(title)
            st.markdown(body)
            if ablation.get(k):
                st.caption(f"Without it, {pct(ablation[k]['false_accept_rate'])} of harmful patches get through.")

    if live:
        c = live["combined"]
        st.space("large")
        eyebrow("On real Gemini output")
        with st.container(horizontal=True):
            st.metric("Accepted on the first attempt", f"{c['single_shot_accepted_patchgate']} / {c['findings']}", border=True)
            st.metric("Re-lint vs PatchGate disagreements", c["relint_accept_patchgate_reject"], border=True,
                      help=f"95% upper bound {pct(c['upper95_disagreement_rate'])} (rule of three).")
            st.metric("Model requests", c["llm_calls"], border=True, help="Free tier, no cost.")


# ---------------------------------------------------------------- repair view

def render_repair() -> None:
    left, right = st.columns([3, 2], gap="large")
    text, name = "", "pasted.yaml"
    with left, st.container(key="artifact-manifest", height="stretch"):
        st.subheader("Manifest")
        src = st.segmented_control("Source", ["Example", "Upload", "Paste"], required=True, key="source")
        if src == "Example":
            files = sorted(p.name for p in EXAMPLES.glob("*.yaml"))
            if st.session_state["example"] not in files:
                st.session_state["example"] = files[0]
            name = st.selectbox("Example manifest", files, key="example")
            text = (EXAMPLES / name).read_text(encoding="utf-8")
        elif src == "Upload":
            up = st.file_uploader("Kubernetes YAML, up to 1 MB", type=["yaml", "yml"])
            if up is not None:
                if up.size > 1_000_000:
                    st.error("The file is larger than 1 MB.", icon=":material/error:")
                else:
                    st.session_state["uploaded"] = (up.name, up.getvalue().decode("utf-8", errors="replace"))
            if st.session_state.get("uploaded"):
                name, text = st.session_state["uploaded"]
                if up is None:
                    st.caption(f"Using previously uploaded **{name}**.")
        else:
            text = st.text_area("Paste YAML", height=220, key="pasted", placeholder="apiVersion: apps/v1\nkind: Deployment\n…")

    with right, st.container(key="artifact-settings", height="stretch"):
        st.subheader("Proposer")
        options = ["simulated", "template"] + (["gemini"] if settings.gemini_configured else [])
        if st.session_state["proposer"] not in options:
            st.session_state["proposer"] = "simulated"
        proposer_kind = st.segmented_control("Patch proposer", options, required=True,
                                             format_func=str.capitalize, key="proposer")
        st.caption(PROPOSER_HELP[proposer_kind])
        if proposer_kind == "gemini":
            st.caption(f"Model `{settings.gemini_model}` · at most {settings.max_llm_calls} requests per run.")
        elif not settings.gemini_configured:
            st.caption("Set `GEMINI_API_KEY` in `.env` to enable the live Gemini proposer.")
        max_attempts = st.slider("Attempts per finding", 1, 6, key="attempts")
        fallback = st.toggle("Fall back to template fixes", key="fallback",
                             help="If the proposer fails or is unavailable, try the deterministic fix (still gated).")

    st.session_state["manifest_text"], st.session_state["manifest_name"] = text, name
    if not text:
        st.info("Choose, upload or paste a manifest to begin.", icon=":material/upload_file:")
        return
    try:
        manifest = load_manifest(text)
    except ManifestError as exc:
        st.error(str(exc), title="Cannot load this manifest", icon=":material/error:")
        return

    findings = scan(manifest)
    auto = [f for f in findings if CONTROLS[f.control_id].auto_repairable]
    st.space("medium")
    st.header("Findings")
    if not findings:
        st.success("No misconfigurations found by the 11 controls.", icon=":material/check_circle:")
        return
    sev = pd.Series([CONTROLS[f.control_id].severity for f in findings]).value_counts()
    with st.container(horizontal=True):
        st.metric("High severity", int(sev.get("high", 0)), border=True)
        st.metric("Medium severity", int(sev.get("medium", 0)), border=True)
        st.metric("Low severity", int(sev.get("low", 0)), border=True)
        st.metric("Needs a human", len(findings) - len(auto), border=True,
                  help="Controls whose every fix changes behaviour (hostPath, image version) are never auto-repaired.")
    df = pd.DataFrame([f.to_dict() for f in findings])
    st.dataframe(
        df[["control_id", "title", "severity", "resource", "subject", "message", "auto_repairable"]],
        hide_index=True, alt="Findings detected in the manifest",
        column_config={
            "control_id": st.column_config.TextColumn("Control", width="small"),
            "title": st.column_config.TextColumn("Check"),
            "severity": st.column_config.TextColumn("Severity", width="small"),
            "resource": st.column_config.TextColumn("Resource"),
            "subject": st.column_config.TextColumn("Subject", width="small"),
            "message": st.column_config.TextColumn("Problem", width="large"),
            "auto_repairable": st.column_config.CheckboxColumn("Auto-repair", width="small"),
        },
    )
    if proposer_kind == "gemini" and len(auto) > 18:
        st.warning(f"This manifest has {len(auto)} auto-repairable findings, so a Gemini run needs at least that many "
                   "requests. On the free tier (about 20 requests per day per model) the run will likely degrade to "
                   "template fixes. Try a smaller example, or the simulated proposer.",
                   title="Free-tier quota", icon=":material/warning:")

    with st.container(horizontal=True, vertical_alignment="center"):
        clicked = st.button("Repair and verify", type="primary", icon=":material/auto_fix_high:", disabled=not auto,
                            key="repair_btn")
        st.caption(f"{len(auto)} auto-repairable · up to {max_attempts} attempts each")
    if clicked:
        try:
            proposer = make_proposer(proposer_kind, settings)
        except ConfigError as exc:
            st.error(str(exc), title="Configuration", icon=":material/error:")
            return
        with st.spinner("Proposing patches and running the gate…"):
            report = repair_manifest(manifest, proposer, max_attempts=max_attempts,
                                     fallback_to_template=fallback, source_text=text)
            run_id = AuditStore(settings.db_path).record(report, name, settings.gemini_model if proposer_kind == "gemini" else None)
        st.session_state["report"] = (report, text, run_id)

    stored = st.session_state.get("report")
    if not stored or stored[1] != text:
        return
    report, original, run_id = stored
    s = report.summary
    st.space("medium")
    st.header("Repair result")
    st.caption(f"Audit run #{run_id} · proposer {report.proposer}"
               + (" (simulated candidates, not Gemini output)" if report.proposer == "simulated" else "")
               + f" · {report.llm_calls} model requests")
    with st.container(horizontal=True):
        st.metric("Findings before", s["findings_before"], border=True)
        st.metric("Findings after", s["findings_after"], border=True)
        st.metric("Repaired", s.get("repaired", 0), border=True)
        st.metric("Needs a human", s.get("manual", 0) + s.get("unrepaired", 0), border=True)
        st.metric("Candidates rejected", s["rejected_candidates"], border=True,
                  help="Proposed patches the gate refused, each with its reasons below.")
    if report.degraded:
        st.warning(report.degraded, title="The proposer degraded during the run; remaining findings used template fixes",
                   icon=":material/warning:")

    st.subheader("Per finding")
    for o in report.outcomes:
        f = o.finding
        with st.expander(f"{f['control_id']} · {f['title']} — {f['resource']} [{f['subject']}] · {STATUS_LABEL[o.status]}",
                         icon=STATUS_ICON[o.status]):
            st.markdown(f["message"])
            if o.status == "manual":
                st.info("Every fix for this control changes behaviour (where data lives, or which software runs), "
                        "so PatchGate leaves it for a human.", icon=":material/person:")
            for a in o.attempts:
                with st.container(horizontal=True, vertical_alignment="center"):
                    if a.accepted:
                        st.badge("Accepted", icon=":material/check:", color="green")
                    else:
                        st.badge("Rejected", icon=":material/close:", color="red")
                    simulated = " · simulated" if a.simulated and a.proposer != "simulated" else ""
                    st.markdown(f"**Attempt {a.attempt}** · {a.proposer}{simulated}")
                if a.rationale:
                    st.caption(a.rationale)
                if a.checks:
                    st.dataframe(
                        pd.DataFrame([{"check": ch["name"], "passed": ch["passed"], "details": "; ".join(ch["details"])}
                                      for ch in a.checks]),
                        hide_index=True, alt=f"Gate checks for attempt {a.attempt}",
                        column_config={"check": st.column_config.TextColumn("Check", width="small"),
                                       "passed": st.column_config.CheckboxColumn("Passed", width="small"),
                                       "details": st.column_config.TextColumn("Details", width="large")},
                    )
                elif a.reasons:
                    for r in a.reasons:
                        st.caption(r)
                if a.patch is not None:
                    st.code(json.dumps(a.patch, indent=2), language="json")
            for ra in o.runtime_assumptions:
                st.caption(f":material/visibility: Validate at runtime: {ra}")

    st.subheader("Diff")
    diff = "".join(difflib.unified_diff(load_manifest(original).to_yaml().splitlines(True),
                                        report.repaired_yaml.splitlines(True), "original", "repaired"))
    with st.container(key="card-diff"):
        st.code(diff or "(no changes)", language="diff", height=420)
    with st.container(horizontal=True):
        st.download_button("Repaired YAML", report.repaired_yaml, "repaired.yaml", type="primary",
                           icon=":material/download:", on_click="ignore")
        st.download_button("JSON patches", json.dumps(report.patches, indent=2), "patches.json",
                           icon=":material/data_object:", on_click="ignore")
        st.download_button("Full report", json.dumps(report.to_dict(), indent=2), "report.json",
                           icon=":material/description:", on_click="ignore")


# ---------------------------------------------------------------- gate playground

def render_gate() -> None:
    st.header("Gate playground")
    st.markdown("Paste a candidate JSON Patch, from Gemini, another tool or a person, and compare how the "
                "re-lint baselines and PatchGate judge it.")
    text = st.session_state.get("manifest_text") or (EXAMPLES / DEFAULT_EXAMPLE).read_text(encoding="utf-8")
    name = st.session_state.get("manifest_name") if st.session_state.get("manifest_text") else DEFAULT_EXAMPLE
    try:
        manifest = load_manifest(text)
    except ManifestError as exc:
        st.error(str(exc), title="Cannot load the manifest chosen in the Repair view", icon=":material/error:")
        return
    st.caption(f"Manifest: **{name}** · choose another in the Repair view.")
    fs = [f for f in scan(manifest) if CONTROLS[f.control_id].auto_repairable]
    if not fs:
        st.success("This manifest has no auto-repairable findings.", icon=":material/check_circle:")
        return

    by_key = {":".join(map(str, f.key)): f for f in fs}
    if st.session_state.get("gate_finding") not in by_key:
        st.session_state.pop("gate_finding", None)
    left, right = st.columns([3, 2], gap="large")
    with left, st.container(key="artifact-gate", height="stretch"):
        fkey = st.selectbox("Finding", list(by_key), key="gate_finding",
                            format_func=lambda k: f"{by_key[k].control_id} {by_key[k].resource_ref} [{by_key[k].subject}] — {by_key[k].message}")
        f = by_key[fkey]
        res = manifest.resources[f.resource_index].obj
        starts = {"template": template_fix(res, f) or []}
        bad = overbroad_example(res, f)
        if bad:
            starts["overbroad"] = bad
        labels = {"template": "Template fix", "overbroad": "Over-broad rewrite (demo)"}
        if st.session_state["gate_start"] not in starts:
            st.session_state["gate_start"] = "template"
        start = st.segmented_control("Start from", list(starts), format_func=labels.get, required=True, key="gate_start")
        patch_text = st.text_area("Candidate JSON Patch", value=json.dumps(starts[start], indent=2), height=240,
                                  key=f"patch-{fkey}-{start}")
        go = st.button("Verify with all gates", type="primary", icon=":material/rule:", key="verify_btn")
    with right, st.container(key="card-contract", height="stretch"):
        st.subheader("Repair contract")
        st.caption(f"{CONTROLS[f.control_id].title} may only change:")
        for p in CONTROLS[f.control_id].allowed_patterns(f):
            st.markdown(f"`{p}`")
        st.caption("Behaviour-defining fields (identity, labels, selectors, images, ports, env, existing volumes "
                   "and mounts) are protected regardless.")

    if not go:
        return
    try:
        patch = json.loads(patch_text)
    except json.JSONDecodeError as exc:
        st.error(f"Line {exc.lineno}, column {exc.colno}: {exc.msg}", title="Not valid JSON", icon=":material/error:")
        return
    verdicts = {g: verify(res, f, patch, GATES[g])[0] for g in BASELINES}
    st.space("small")
    cols = st.columns(len(BASELINES))
    for col, g in zip(cols, BASELINES):
        v = verdicts[g]
        with col, st.container(key=f"artifact-verdict-{g}" if g == "patchgate" else f"card-verdict-{g}", height="stretch"):
            st.caption(GATE_LABELS[g].upper() if g == "patchgate" else f"BASELINE · {GATE_LABELS[g].upper()}")
            if v.accepted:
                st.markdown("### :material/check_circle: Accept")
            else:
                st.markdown("### :material/cancel: Reject")
            st.caption(f"{len(v.reasons)} reason{'s' if len(v.reasons) != 1 else ''}")
    reasons = [{"gate": GATE_LABELS[g], "reason": r} for g in BASELINES for r in verdicts[g].reasons]
    if reasons:
        st.dataframe(pd.DataFrame(reasons), hide_index=True, alt="Reasons each gate gave for rejecting the patch",
                     column_config={"gate": st.column_config.TextColumn("Gate"),
                                    "reason": st.column_config.TextColumn("Reason", width="large")})


# ---------------------------------------------------------------- evaluation view

def render_evaluation() -> None:
    if not (bench or challenge or live):
        st.info("No results yet. Run `python -m evaluation.run_eval` and `python -m evaluation.challenge_set` "
                "from the project root.", icon=":material/monitoring:")
        return
    if bench:
        m = bench["metrics"]
        with st.container(key="peach"):
            eyebrow("Headline result · held-out benchmark", key="peach-eyebrow")
            st.markdown(f"## Re-linting let through {pct(m['relint-full']['false_accept_rate'])} of harmful patches. "
                        f"PatchGate let through {pct(m['patchgate']['false_accept_rate'])}.")
            st.caption(f"{bench['counts']['candidates']:,} labelled candidates ({bench['counts']['valid']:,} valid, "
                       f"{bench['counts']['invalid']:,} harmful), seed {bench['seed']}. The harmful categories were written "
                       "by the gate's author, so this measures coverage of that taxonomy, not a real-world error rate.")
        st.space("medium")
        st.header("Benchmark")
        rows = pd.DataFrame([{"gate": GATE_LABELS[g], "key": g, **m[g]} for g in GATE_LABELS if g in m])
        left, right = st.columns([3, 2], gap="large")
        with left, st.container(key="artifact-chart", height="stretch"):
            st.subheader("False-accept rate by gate")
            base = alt.Chart(rows).encode(
                x=alt.X("false_accept_rate:Q", title="Harmful patches accepted",
                        axis=alt.Axis(format="%", grid=False), scale=alt.Scale(domain=[0, 1])),
                y=alt.Y("gate:N", sort=list(GATE_LABELS.values()), title=None, axis=alt.Axis(labelLimit=260)),
                tooltip=[alt.Tooltip("gate:N", title="Gate"),
                         alt.Tooltip("false_accept_rate:Q", title="False-accept rate", format=".1%"),
                         alt.Tooltip("invalid_accepted:Q", title="Harmful accepted", format=",")],
            )
            bars = base.mark_bar(cornerRadiusEnd=6, height=22).encode(
                color=alt.condition(alt.datum.key == "patchgate", alt.value("#5d2a1a"), alt.value("#a3a6af")))
            labels = base.mark_text(align="left", dx=8, fontSize=14).encode(
                text=alt.Text("false_accept_rate:Q", format=".1%"),
                color=alt.condition(alt.datum.key == "patchgate", alt.value("#5d2a1a"), alt.value("#777b86")))
            chart = (bars + labels).properties(height=280)
            st.altair_chart(chart, alt="Bar chart of false-accept rate for each gate; PatchGate is at 0 percent")
        with right, st.container(key="card-ablation", height="stretch"):
            st.subheader("Ablation")
            st.caption("Remove one PatchGate check and harmful patches slip through again.")
            for g in ("patchgate-no-structural", "patchgate-no-scope", "patchgate-no-invariants"):
                st.metric(GATE_LABELS[g], pct(m[g]["false_accept_rate"]), border=True,
                          help=f"{m[g]['invalid_accepted']:,} harmful candidates accepted without this check.")
        table = rows.assign(false_accept_rate=rows["false_accept_rate"] * 100, false_reject_rate=rows["false_reject_rate"] * 100)
        st.dataframe(
            table[["gate", "false_accept_rate", "false_reject_rate", "reject_precision", "reject_recall", "f1", "latency_ms_mean"]],
            hide_index=True, alt="Benchmark metrics for every gate configuration",
            column_config={
                "gate": st.column_config.TextColumn("Gate"),
                "false_accept_rate": st.column_config.NumberColumn("False accepts", format="%.1f%%"),
                "false_reject_rate": st.column_config.NumberColumn("False rejects", format="%.1f%%"),
                "reject_precision": st.column_config.NumberColumn("Precision", format="%.3f"),
                "reject_recall": st.column_config.NumberColumn("Recall", format="%.3f"),
                "f1": st.column_config.NumberColumn("F1", format="%.3f"),
                "latency_ms_mean": st.column_config.NumberColumn("Mean ms", format="%.3f"),
            },
        )

    if challenge:
        st.space("medium")
        st.header("Challenge set")
        st.markdown("Twenty-one hand-written cases designed to find the gate's limits, frozen before the first run.")
        s = challenge["summary"]
        with st.container(horizontal=True):
            st.metric("Re-lint: harmful accepted", f"{s['relint-full']['false_accepts']} / {s['relint-full']['invalid']}", border=True)
            st.metric("PatchGate: harmful accepted", f"{s['patchgate']['false_accepts']} / {s['patchgate']['invalid']}", border=True,
                      help="All runtime-only breakage that static checks cannot see.")
            st.metric("Re-lint: valid rejected", f"{s['relint-full']['false_rejects']} / {s['relint-full']['valid']}", border=True)
            st.metric("PatchGate: valid rejected", f"{s['patchgate']['false_rejects']} / {s['patchgate']['valid']}", border=True,
                      help="Harmless extras outside the strict repair contracts.")
        cases = pd.DataFrame([c for c in challenge["cases"] if "error" not in c])
        st.dataframe(
            cases[["id", "control", "valid", "relint-full", "patchgate", "patchgate_correct", "why"]],
            hide_index=True, alt="Challenge-set cases with each gate's verdict",
            column_config={
                "id": st.column_config.TextColumn("Case"),
                "control": st.column_config.TextColumn("Control", width="small"),
                "valid": st.column_config.CheckboxColumn("Valid", help="Ground truth: the patch is a legitimate fix"),
                "relint-full": st.column_config.CheckboxColumn("Re-lint", help="Accepted by the re-lint baseline"),
                "patchgate": st.column_config.CheckboxColumn("PatchGate", help="Accepted by PatchGate"),
                "patchgate_correct": st.column_config.CheckboxColumn("Correct", help="PatchGate's verdict matches the ground truth"),
                "why": st.column_config.TextColumn("Why", width="large"),
            },
        )

    if live:
        c = live["combined"]
        st.space("medium")
        st.header("Live Gemini")
        st.markdown(f"Real Gemini repairs on {c['findings']} findings over two days, limited by the free tier.")
        with st.container(horizontal=True):
            st.metric("Accepted first attempt", f"{c['single_shot_accepted_patchgate']} / {c['findings']}", border=True)
            st.metric("Malformed outputs", c["single_shot_malformed"], border=True)
            st.metric("Re-lint vs PatchGate disagreements", c["relint_accept_patchgate_reject"], border=True,
                      help=f"95% upper bound on the true rate: {pct(c['upper95_disagreement_rate'])} (rule of three).")
            st.metric("Model requests", c["llm_calls"], border=True,
                      help=f"{c['tokens_in']:,} input and {c['tokens_out']:,} output tokens.")
        st.caption("On these simple findings Gemini's patches were minimal and in-contract: the gate blocked none of "
                   "them, and had nothing harmful to catch.")
        st.dataframe(pd.DataFrame(live["runs"]), hide_index=True, alt="Individual live Gemini runs",
                     column_config={"file": st.column_config.TextColumn("Result file"),
                                    "model": st.column_config.TextColumn("Model"),
                                    "findings": st.column_config.NumberColumn("Findings"),
                                    "llm_calls": st.column_config.NumberColumn("Requests"),
                                    "tokens_in": st.column_config.NumberColumn("Tokens in", format="localized"),
                                    "tokens_out": st.column_config.NumberColumn("Tokens out", format="localized"),
                                    "stopped_early": st.column_config.CheckboxColumn("Stopped by quota")})


# ---------------------------------------------------------------- audit view

def render_audit() -> None:
    st.header("Audit log")
    st.markdown("Every repair run is recorded with each candidate patch and the gate's verdict. "
                "Only a SHA-256 of the manifest is stored, never its contents.")
    runs = AuditStore(settings.db_path).list_runs(200)
    if not runs:
        st.info("No runs recorded yet. Repair a manifest to create one.", icon=":material/history:")
        return
    df = pd.DataFrame([{
        "run": r["id"],
        "when": r["created_at"].replace("T", " ").replace("+00:00", ""),
        "manifest": r["source_name"],
        "proposer": r["proposer"],
        "model": r["model"] or "—",
        "requests": r["llm_calls"],
        "before": r["summary"].get("findings_before", 0),
        "after": r["summary"].get("findings_after", 0),
        "repaired": r["summary"].get("repaired", 0),
        "human": r["summary"].get("manual", 0) + r["summary"].get("unrepaired", 0),
        "rejected": r["summary"].get("rejected_candidates", 0),
        "degraded": bool(r["degraded"]),
    } for r in runs])
    with st.container(horizontal=True):
        st.metric("Runs", len(df), border=True)
        st.metric("Findings repaired", int(df["repaired"].sum()), border=True)
        st.metric("Candidates rejected", int(df["rejected"].sum()), border=True)
        st.metric("Model requests", int(df["requests"].sum()), border=True)
    st.dataframe(df, hide_index=True, alt="Recorded repair runs",
                 column_config={"run": st.column_config.NumberColumn("Run", width="small"),
                                "when": st.column_config.TextColumn("When (UTC)"),
                                "manifest": st.column_config.TextColumn("Manifest"),
                                "proposer": st.column_config.TextColumn("Proposer"),
                                "model": st.column_config.TextColumn("Model"),
                                "requests": st.column_config.NumberColumn("Requests", width="small"),
                                "before": st.column_config.NumberColumn("Before", width="small", help="Findings before repair"),
                                "after": st.column_config.NumberColumn("After", width="small", help="Findings after repair"),
                                "repaired": st.column_config.NumberColumn("Repaired", width="small"),
                                "human": st.column_config.NumberColumn("Human", width="small", help="Findings left for a human (manual or unrepaired)"),
                                "rejected": st.column_config.NumberColumn("Rejected", width="small",
                                                                          help="Candidate patches the gate refused"),
                                "degraded": st.column_config.CheckboxColumn("Degraded", width="small",
                                                                            help="The proposer failed mid-run and template fixes were used")})


{"overview": render_overview, "repair": render_repair, "gate": render_gate, "evaluation": render_evaluation,
 "audit": render_audit}[view]()
