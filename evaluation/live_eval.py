"""RQ2 (requires GEMINI_API_KEY): what does the gate do to *real* Gemini repairs?

For a sample of findings from the seeded corpus it measures
  * single-shot Gemini, judged by the re-lint baseline gate and by PatchGate, and
  * the PatchGate loop (up to K attempts with verifier feedback).
Candidates that re-lint accepts but PatchGate rejects are exported for MANUAL labelling, because only a
human can say whether such a rejection was a true catch or a false reject.

    python -m evaluation.live_eval --findings 30 --attempts 3 --max-calls 120

Spending is bounded by --max-calls (each retry counts). Nothing here runs in the normal test suite.
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter
from pathlib import Path

from patchgate.checks import CONTROLS, scan_object
from patchgate.config import ConfigError, load_settings
from patchgate.llm import BudgetExceeded, CallBudget, GeminiProposer, LLMUnavailable, ProposalRequest
from patchgate.verifier import GATES, verify

from .corpus import generate_workload


def sample_findings(seed: int, n: int):
    rng = random.Random(seed)
    pool = []
    for i in range(400):
        res = generate_workload(rng, i)
        pool += [(res, f) for f in scan_object(res, 0) if CONTROLS[f.control_id].auto_repairable]
    random.Random(seed + 1).shuffle(pool)
    # stratify: round-robin over controls so rare controls are represented
    by_control: dict[str, list] = {}
    for item in pool:
        by_control.setdefault(item[1].control_id, []).append(item)
    out = []
    while len(out) < n and any(by_control.values()):
        for cid in sorted(by_control):
            if by_control[cid] and len(out) < n:
                out.append(by_control[cid].pop())
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seed", type=int, default=99)
    ap.add_argument("--findings", type=int, default=30)
    ap.add_argument("--attempts", type=int, default=3)
    ap.add_argument("--max-calls", type=int, default=120)
    ap.add_argument("--out", default="evaluation/results/live_gemini.json")
    args = ap.parse_args(argv)
    settings = load_settings()
    try:
        settings.require_gemini()
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    proposer = GeminiProposer(settings, budget=CallBudget(args.max_calls))
    rows, stop = [], None
    for res, f in sample_findings(args.seed, args.findings):
        row = {"control_id": f.control_id, "kind": res["kind"], "subject": f.subject, "attempts": []}
        feedback: list[str] = []
        try:
            for attempt in range(1, args.attempts + 1):
                prop = proposer.propose(ProposalRequest(res, f, attempt, feedback))
                if prop.patch is None:
                    row["attempts"].append({"patch": None, "error": prop.error})
                    feedback = [prop.error or "no patch"]
                    continue
                verdicts = {g: verify(res, f, prop.patch, GATES[g])[0] for g in ("relint-full", "patchgate")}
                row["attempts"].append({"patch": prop.patch, "rationale": prop.rationale,
                                        "relint_full": verdicts["relint-full"].accepted,
                                        "patchgate": verdicts["patchgate"].accepted,
                                        "patchgate_reasons": verdicts["patchgate"].reasons})
                if verdicts["patchgate"].accepted:
                    break
                feedback = verdicts["patchgate"].reasons
        except (BudgetExceeded, LLMUnavailable) as exc:
            stop = str(exc)
            if row["attempts"]:
                rows.append(row)
            break
        rows.append(row)

    first = [r["attempts"][0] for r in rows if r["attempts"]]
    summary = {
        "model": settings.gemini_model, "findings": len(rows), "llm_calls": proposer.budget.used,
        "tokens_in": proposer.tokens_in, "tokens_out": proposer.tokens_out, "stopped_early": stop,
        "single_shot_malformed": sum(a["patch"] is None for a in first),
        "single_shot_accepted_relint_full": sum(bool(a.get("relint_full")) for a in first),
        "single_shot_accepted_patchgate": sum(bool(a.get("patchgate")) for a in first),
        "loop_accepted_patchgate": sum(any(a.get("patchgate") for a in r["attempts"]) for r in rows),
        "mean_attempts_when_accepted": (lambda xs: round(sum(xs) / len(xs), 2) if xs else None)(
            [next(i for i, a in enumerate(r["attempts"], 1) if a.get("patchgate")) for r in rows if any(a.get("patchgate") for a in r["attempts"])]),
        "by_control": dict(Counter(r["control_id"] for r in rows)),
    }
    disagreements = [{"control_id": r["control_id"], **a} for r in rows for a in r["attempts"]
                     if a.get("relint_full") and not a.get("patchgate")]
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"summary": summary, "needs_manual_label": disagreements, "rows": rows}, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    print(f"{len(disagreements)} relint-accepted / PatchGate-rejected candidates exported for manual labelling -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
