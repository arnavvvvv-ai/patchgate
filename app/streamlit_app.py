"""PatchGate demo UI.   Run:  streamlit run app/streamlit_app.py"""
from __future__ import annotations

import difflib
import json
from pathlib import Path

import pandas as pd
import streamlit as st

from patchgate.checks import CONTROLS, scan
from patchgate.config import ConfigError, load_settings
from patchgate.fixers import template_fix
from patchgate.llm import make_proposer
from patchgate.manifest import ManifestError, load_manifest
from patchgate.repair import repair_manifest
from patchgate.store import AuditStore
from patchgate.verifier import GATES, verify

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
RESULTS = ROOT / "evaluation" / "results"
GATE_LABELS = {"apply-only": "Baseline: patch applies", "relint-target": "Baseline: re-lint target",
               "relint-full": "Baseline: re-lint all", "patchgate": "PatchGate (full)"}

st.set_page_config(page_title="PatchGate", layout="wide")
settings = load_settings()

with st.sidebar:
    st.title("PatchGate")
    st.caption("Verified, behaviour-preserving repair of Kubernetes misconfigurations")
    options = ["simulated", "template"] + (["gemini"] if settings.gemini_configured else [])
    proposer_kind = st.radio("Patch proposer", options, help="gemini appears when GEMINI_API_KEY is configured")
    if proposer_kind == "simulated":
        st.info("Simulated: replays HAND-WRITTEN example candidates (some deliberately wrong). No Gemini call is made.")
    elif proposer_kind == "gemini":
        st.success(f"Live Gemini: {settings.gemini_model} (max {settings.max_llm_calls} calls/run)")
    if not settings.gemini_configured:
        st.warning("GEMINI_API_KEY not set: live Gemini proposer disabled. See README → Configuration.")
    max_attempts = st.slider("Attempts per finding", 1, 6, settings.max_attempts)
    fallback = st.checkbox("Fall back to template fix", value=True)

tab_repair, tab_gate, tab_eval, tab_audit = st.tabs(["Repair", "Gate playground", "Evaluation", "Audit log"])

# ------------------------------------------------------------------ input
with tab_repair:
    src = st.radio("Manifest source", ["Example", "Upload", "Paste"], horizontal=True)
    text, name = "", "pasted.yaml"
    if src == "Example":
        files = sorted(p.name for p in EXAMPLES.glob("*.yaml"))
        name = st.selectbox("Example", files)
        text = (EXAMPLES / name).read_text(encoding="utf-8")
    elif src == "Upload":
        up = st.file_uploader("Kubernetes YAML (max 1 MB)", type=["yaml", "yml"])
        if up is not None:
            if up.size > 1_000_000:
                st.error("File larger than 1 MB")
            else:
                text, name = up.getvalue().decode("utf-8", errors="replace"), up.name
    else:
        text = st.text_area("Paste YAML", height=260)
    st.session_state["manifest_text"] = text

    if text:
        try:
            manifest = load_manifest(text)
        except ManifestError as exc:
            st.error(f"Cannot load manifest: {exc}")
            manifest = None
        if manifest is not None:
            findings = scan(manifest)
            st.subheader(f"Findings ({len(findings)})")
            if findings:
                st.dataframe(pd.DataFrame([f.to_dict() for f in findings])[
                    ["control_id", "severity", "resource", "subject", "message", "auto_repairable"]],
                    width="stretch", hide_index=True)
            if st.button("Repair", type="primary", disabled=not findings):
                try:
                    proposer = make_proposer(proposer_kind, settings)
                except ConfigError as exc:
                    st.error(str(exc))
                    st.stop()
                with st.spinner("Proposing and verifying patches..."):
                    report = repair_manifest(manifest, proposer, max_attempts=max_attempts,
                                             fallback_to_template=fallback, source_text=text)
                    run_id = AuditStore(settings.db_path).record(report, name, settings.gemini_model if proposer_kind == "gemini" else None)
                st.session_state["report"] = (report, text, run_id)

    if "report" in st.session_state and st.session_state["report"][1] == text:
        report, original, run_id = st.session_state["report"]
        s = report.summary
        c = st.columns(5)
        c[0].metric("Findings before", s["findings_before"])
        c[1].metric("Findings after", s["findings_after"])
        c[2].metric("Repaired", s.get("repaired", 0))
        c[3].metric("Needs human", s.get("manual", 0) + s.get("unrepaired", 0))
        c[4].metric("Candidates rejected", s["rejected_candidates"])
        if report.degraded:
            st.warning(f"Proposer degraded during the run (fell back to templates): {report.degraded}")
        st.caption(f"Audit run #{run_id} · proposer: {report.proposer} · LLM calls: {report.llm_calls}")
        for o in report.outcomes:
            f = o.finding
            icon = {"repaired": "✅", "manual": "🧑‍🔧", "unrepaired": "⚠️", "resolved-by-other": "↪️"}[o.status]
            with st.expander(f"{icon} {f['control_id']} {f['title']} — {f['resource']} [{f['subject']}] → {o.status}"):
                st.write(f["message"])
                if o.status == "manual":
                    st.info("Behaviour-changing fix (e.g. replacing hostPath, choosing an image version): left for a human.")
                for a in o.attempts:
                    st.markdown(f"**Attempt {a.attempt} · {a.proposer}{' (simulated)' if a.simulated else ''} · "
                                f"{'ACCEPTED' if a.accepted else 'REJECTED'}**" + (f" — {a.rationale}" if a.rationale else ""))
                    if a.patch is not None:
                        st.code(json.dumps(a.patch, indent=2), language="json")
                    if a.checks:
                        st.dataframe(pd.DataFrame([{"check": ch["name"], "passed": ch["passed"], "details": "; ".join(ch["details"])}
                                                   for ch in a.checks]), hide_index=True, width="stretch")
                    elif a.reasons:
                        st.write(a.reasons)
                for ra in o.runtime_assumptions:
                    st.caption(f"Validate at runtime: {ra}")
        st.subheader("Diff")
        diff = "".join(difflib.unified_diff(load_manifest(original).to_yaml().splitlines(True),
                                            report.repaired_yaml.splitlines(True), "original", "repaired"))
        st.code(diff or "(no changes)", language="diff")
        d = st.columns(3)
        d[0].download_button("Repaired YAML", report.repaired_yaml, "repaired.yaml")
        d[1].download_button("JSON patches", json.dumps(report.patches, indent=2), "patches.json")
        d[2].download_button("Full report", json.dumps(report.to_dict(), indent=2), "report.json")

# ------------------------------------------------------------------ gate playground
with tab_gate:
    st.write("Paste any candidate JSON Patch (from Gemini, another tool or a human) and compare how the "
             "baseline gates and PatchGate judge it.")
    text = st.session_state.get("manifest_text", "")
    try:
        manifest = load_manifest(text) if text else None
    except ManifestError:
        manifest = None
    if manifest is None:
        st.info("Choose a manifest in the Repair tab first.")
    else:
        fs = [f for f in scan(manifest) if CONTROLS[f.control_id].auto_repairable]
        if not fs:
            st.success("No auto-repairable findings in this manifest.")
        else:
            f = st.selectbox("Finding", fs, format_func=lambda x: f"{x.control_id} {x.resource_ref} [{x.subject}] — {x.message}")
            res = manifest.resources[f.resource_index].obj
            st.caption("Repair contract (allowed paths): " + ", ".join(f"`{p}`" for p in CONTROLS[f.control_id].allowed_patterns(f)))
            default = json.dumps(template_fix(res, f) or [], indent=2)
            patch_text = st.text_area("Candidate JSON Patch", value=default, height=220, key=f"patch-{f.key}")
            if st.button("Verify with all gates"):
                try:
                    patch = json.loads(patch_text)
                except json.JSONDecodeError as exc:
                    st.error(f"Not valid JSON: {exc}")
                    st.stop()
                rows = []
                for g in ["apply-only", "relint-target", "relint-full", "patchgate"]:
                    v, _ = verify(res, f, patch, GATES[g])
                    rows.append({"gate": GATE_LABELS[g], "verdict": "ACCEPT" if v.accepted else "REJECT",
                                 "reasons": "; ".join(v.reasons)})
                st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")

# ------------------------------------------------------------------ evaluation
with tab_eval:
    st.write("Measured results produced by `python -m evaluation.run_eval` and `python -m evaluation.challenge_set`.")
    summaries = sorted(RESULTS.glob("*_summary.json"))
    if not summaries:
        st.info("No results yet. Run the evaluation commands from the README.")
    for p in summaries:
        data = json.loads(p.read_text(encoding="utf-8"))
        st.subheader(f"{p.stem} — {data['counts']['candidates']} candidates ({data['counts']['valid']} valid / {data['counts']['invalid']} invalid)")
        st.dataframe(pd.DataFrame(data["metrics"]).T[["false_accept_rate", "false_reject_rate", "reject_precision",
                                                       "reject_recall", "f1", "latency_ms_mean"]], width="stretch")
    ch = RESULTS / "challenge_set.json"
    if ch.exists():
        data = json.loads(ch.read_text(encoding="utf-8"))
        st.subheader("Hand-written challenge set")
        st.json(data["summary"])
        st.dataframe(pd.DataFrame(data["cases"])[["id", "valid", "relint-full", "patchgate", "patchgate_correct", "why"]],
                     hide_index=True, width="stretch")

# ------------------------------------------------------------------ audit log
with tab_audit:
    runs = AuditStore(settings.db_path).list_runs(100)
    if not runs:
        st.info("No runs recorded yet.")
    else:
        st.dataframe(pd.DataFrame([{**{k: r[k] for k in ("id", "created_at", "source_name", "proposer", "model", "llm_calls")},
                                    **r["summary"]} for r in runs]), hide_index=True, width="stretch")
