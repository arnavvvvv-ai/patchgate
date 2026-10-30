"""Merge every live-Gemini result file into one summary.

    python -m evaluation.merge_live

Reads evaluation/results/live_gemini_*.json and writes live_gemini_combined.json. With zero observed
events in n trials, the 95% upper bound uses the "rule of three" (3/n).
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

RESULTS = Path("evaluation/results")


def main() -> int:
    files = sorted(p for p in RESULTS.glob("live_gemini_*.json") if p.name != "live_gemini_combined.json")
    runs, rows = [], []
    for p in files:
        d = json.loads(p.read_text(encoding="utf-8"))
        s = d["summary"]
        runs.append({"file": p.name, "model": s["model"], "findings": s["findings"], "llm_calls": s["llm_calls"],
                     "tokens_in": s["tokens_in"], "tokens_out": s["tokens_out"], "stopped_early": bool(s["stopped_early"])})
        rows += [{**r, "model": s["model"]} for r in d["rows"] if r["attempts"]]
    first = [r["attempts"][0] for r in rows]
    n = len(rows)
    disagreements = sum(1 for a in first if a.get("relint_full") and not a.get("patchgate"))
    combined = {
        "findings": n,
        "by_model": dict(Counter(r["model"] for r in rows)),
        "by_control": dict(sorted(Counter(r["control_id"] for r in rows).items())),
        "llm_calls": sum(r["llm_calls"] for r in runs),
        "tokens_in": sum(r["tokens_in"] for r in runs),
        "tokens_out": sum(r["tokens_out"] for r in runs),
        "single_shot_malformed": sum(a["patch"] is None for a in first),
        "single_shot_accepted_relint_full": sum(bool(a.get("relint_full")) for a in first),
        "single_shot_accepted_patchgate": sum(bool(a.get("patchgate")) for a in first),
        "relint_accept_patchgate_reject": disagreements,
        "loop_accepted_patchgate": sum(any(a.get("patchgate") for a in r["attempts"]) for r in rows),
        "upper95_disagreement_rate": round(3 / n, 3) if n and disagreements == 0 else None,
    }
    out = {"combined": combined, "runs": runs}
    (RESULTS / "live_gemini_combined.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
