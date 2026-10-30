"""RQ1/RQ3: how well does each gate separate valid from invalid candidate patches?

    python -m evaluation.run_eval --seed 2026 --workloads 300 --out evaluation/results

Writes <prefix>_summary.json, <prefix>_candidates.csv and <prefix>_report.md. No network access and
no Gemini calls are made; every number comes from running the gates on the seeded corpus.
"""
from __future__ import annotations

import argparse
import csv
import json
import statistics
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from patchgate.verifier import GATES, verify

from .corpus import Candidate, build_corpus

GATE_ORDER = ["apply-only", "relint-target", "relint-full", "patchgate",
              "patchgate-no-structural", "patchgate-no-scope", "patchgate-no-invariants"]


def evaluate(cands: list[Candidate]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    per_gate: dict[str, Counter] = {g: Counter() for g in GATE_ORDER}
    per_cat: dict[str, dict[str, Counter]] = {g: defaultdict(Counter) for g in GATE_ORDER}
    latency: dict[str, list[float]] = {g: [] for g in GATE_ORDER}
    for c in cands:
        row: dict[str, Any] = {**c.to_json(), "patch": json.dumps(c.patch)}
        for g in GATE_ORDER:
            t0 = time.perf_counter()
            verdict, _ = verify(c.resource, c.finding, c.patch, GATES[g])
            latency[g].append((time.perf_counter() - t0) * 1000)
            acc = verdict.accepted
            row[g] = "accept" if acc else "reject"
            if g == "patchgate":
                row["patchgate_reasons"] = " | ".join(verdict.reasons)[:500]
            key = ("valid" if c.valid else "invalid") + ("_accepted" if acc else "_rejected")
            per_gate[g][key] += 1
            per_cat[g][c.category]["accepted" if acc else "rejected"] += 1
        rows.append(row)

    metrics: dict[str, Any] = {}
    for g in GATE_ORDER:
        k = per_gate[g]
        n_valid = k["valid_accepted"] + k["valid_rejected"]
        n_invalid = k["invalid_accepted"] + k["invalid_rejected"]
        tp = k["invalid_rejected"]           # positive class = "harmful patch caught"
        fp = k["valid_rejected"]
        fn = k["invalid_accepted"]
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        lat = sorted(latency[g])
        metrics[g] = {
            "false_accept_rate": round(fn / n_invalid, 4) if n_invalid else None,
            "false_reject_rate": round(fp / n_valid, 4) if n_valid else None,
            "invalid_accepted": fn, "invalid_total": n_invalid,
            "valid_rejected": fp, "valid_total": n_valid,
            "reject_precision": round(precision, 4), "reject_recall": round(recall, 4),
            "f1": round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0.0,
            "latency_ms_mean": round(statistics.fmean(lat), 3) if lat else None,
            "latency_ms_p95": round(lat[int(0.95 * (len(lat) - 1))], 3) if lat else None,
        }
    categories = sorted({c.category for c in cands})
    cat_table = {cat: {g: dict(per_cat[g][cat]) for g in GATE_ORDER} for cat in categories}
    return {"metrics": metrics, "categories": cat_table, "rows": rows,
            "counts": {"candidates": len(cands), "valid": sum(c.valid for c in cands),
                       "invalid": sum(not c.valid for c in cands),
                       "findings": len({c.case_id.rsplit('-v-', 1)[0].rsplit('-x-', 1)[0] for c in cands}),
                       "by_control": dict(Counter(c.finding.control_id for c in cands))}}


def to_markdown(result: dict[str, Any], seed: int, n: int) -> str:
    m = result["metrics"]
    cnt = result["counts"]
    lines = [f"# Gate discrimination results (seed {seed}, {n} workloads)", "",
             f"Candidates: {cnt['candidates']} ({cnt['valid']} valid, {cnt['invalid']} invalid) "
             f"over {cnt['findings']} findings.", "",
             "| Gate | False-accept rate | False-reject rate | Reject precision | Reject recall | F1 | Mean ms | p95 ms |",
             "|---|---:|---:|---:|---:|---:|---:|---:|"]
    for g in GATE_ORDER:
        x = m[g]
        lines.append(f"| {g} | {x['false_accept_rate']:.3f} ({x['invalid_accepted']}/{x['invalid_total']}) | "
                     f"{x['false_reject_rate']:.3f} ({x['valid_rejected']}/{x['valid_total']}) | {x['reject_precision']:.3f} | "
                     f"{x['reject_recall']:.3f} | {x['f1']:.3f} | {x['latency_ms_mean']:.3f} | {x['latency_ms_p95']:.3f} |")
    lines += ["", "## Acceptances per candidate category (accepted / total)", "",
              "| Category | Label | " + " | ".join(GATE_ORDER) + " |", "|---|---|" + "---:|" * len(GATE_ORDER)]
    valid_cats = {r["category"] for r in result["rows"] if r["valid"]}
    for cat, gates in result["categories"].items():
        cells = []
        for g in GATE_ORDER:
            a = gates[g].get("accepted", 0)
            t = a + gates[g].get("rejected", 0)
            cells.append(f"{a}/{t}")
        lines.append(f"| {cat} | {'valid' if cat in valid_cats else 'invalid'} | " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seed", type=int, default=2026)
    ap.add_argument("--workloads", type=int, default=300)
    ap.add_argument("--out", default="evaluation/results")
    ap.add_argument("--prefix", default=None)
    args = ap.parse_args(argv)
    cands = build_corpus(args.seed, args.workloads)
    result = evaluate(cands)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    prefix = args.prefix or f"seed{args.seed}"
    (out / f"{prefix}_summary.json").write_text(json.dumps({k: v for k, v in result.items() if k != "rows"} |
                                                           {"seed": args.seed, "workloads": args.workloads}, indent=2), encoding="utf-8")
    with (out / f"{prefix}_candidates.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(result["rows"][0].keys()))
        w.writeheader()
        w.writerows(result["rows"])
    md = to_markdown(result, args.seed, args.workloads)
    (out / f"{prefix}_report.md").write_text(md, encoding="utf-8")
    print(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
