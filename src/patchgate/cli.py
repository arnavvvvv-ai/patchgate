"""Command-line interface: scan, repair, verify, runs, check-config."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .checks import CONTROLS, find_matching, scan
from .config import ConfigError, load_settings
from .llm import BudgetExceeded, LLMUnavailable, make_proposer
from .manifest import ManifestError, load_manifest
from .repair import repair_manifest
from .verifier import GATES, verify

SEV_RANK = {"low": 1, "medium": 2, "high": 3}


def _read(path: str) -> str:
    p = Path(path)
    if not p.is_file():
        raise SystemExit(f"error: file not found: {path}")
    return p.read_text(encoding="utf-8")


def _print_findings(findings: list[dict[str, Any]]) -> None:
    if not findings:
        print("No findings.")
        return
    print(f"{'CONTROL':8} {'SEV':6} {'RESOURCE':32} {'SUBJECT':18} MESSAGE")
    for f in findings:
        auto = "" if f["auto_repairable"] else "  [manual]"
        print(f"{f['control_id']:8} {f['severity']:6} {f['resource'][:32]:32} {f['subject'][:18]:18} {f['message']}{auto}")


def cmd_scan(args: argparse.Namespace) -> int:
    manifest = load_manifest(_read(args.file))
    findings = [f.to_dict() for f in scan(manifest)]
    if args.format == "json":
        print(json.dumps(findings, indent=2))
    else:
        _print_findings(findings)
    threshold = SEV_RANK.get(args.fail_on, 0)
    return 1 if threshold and any(SEV_RANK[f["severity"]] >= threshold for f in findings) else 0


def cmd_repair(args: argparse.Namespace) -> int:
    settings = load_settings()
    text = _read(args.file)
    manifest = load_manifest(text)
    proposer = make_proposer(args.proposer, settings)
    report = repair_manifest(manifest, proposer, max_attempts=args.max_attempts or settings.max_attempts,
                             fallback_to_template=not args.no_fallback, source_text=text)
    if args.proposer == "simulated":
        print("NOTE: 'simulated' proposer replays hand-written candidates; no Gemini call was made.\n")
    for o in report.outcomes:
        f = o.finding
        print(f"{f['control_id']} {f['resource']} [{f['subject']}] -> {o.status.upper()}"
              + (f" (accepted from {o.accepted_by})" if o.accepted_by else ""))
        for a in o.attempts:
            mark = "ACCEPT" if a.accepted else "REJECT"
            print(f"    attempt {a.attempt} {a.proposer:18} {mark}")
            for r in a.reasons[:6]:
                print(f"        - {r}")
        for ra in o.runtime_assumptions:
            print(f"    runtime assumption to validate: {ra}")
    print("\nSummary:", json.dumps(report.summary))
    if report.degraded:
        print(f"WARNING: proposer degraded during run: {report.degraded}")
    if args.out:
        out = Path(args.out)
        if out.resolve() == Path(args.file).resolve():
            raise SystemExit("error: refusing to overwrite the input manifest; choose a different --out path")
        out.write_text(report.repaired_yaml, encoding="utf-8")
        print(f"Repaired manifest written to {out}")
    if args.report:
        Path(args.report).write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        print(f"JSON report written to {args.report}")
    if not args.no_audit:
        from .store import AuditStore
        run_id = AuditStore(settings.db_path).record(report, Path(args.file).name,
                                                     settings.gemini_model if args.proposer == "gemini" else None)
        print(f"Audit record: run {run_id} in {settings.db_path}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    manifest = load_manifest(_read(args.file))
    if not 0 <= args.resource < len(manifest.resources):
        raise SystemExit(f"error: --resource must be between 0 and {len(manifest.resources) - 1}")
    res = manifest.resources[args.resource]
    finding = find_matching(scan(manifest), (args.control, args.resource, args.subject))
    if finding is None:
        raise SystemExit(f"error: no {args.control} finding for subject {args.subject!r} in resource {args.resource}")
    patch = json.loads(_read(args.patch))
    gates = list(GATES) if args.compare else [args.gate]
    accepted_main = False
    for g in gates:
        verdict, _ = verify(res.obj, finding, patch, GATES[g])
        if g == args.gate:
            accepted_main = verdict.accepted
        print(f"{g:26} {'ACCEPT' if verdict.accepted else 'REJECT'}")
        for r in verdict.reasons[:8]:
            print(f"    - {r}")
    return 0 if accepted_main else 2


def cmd_runs(args: argparse.Namespace) -> int:
    from .store import AuditStore
    store = AuditStore(load_settings().db_path)
    if args.id is not None:
        run = store.get_run(args.id)
        if run is None:
            raise SystemExit(f"error: run {args.id} not found")
        print(json.dumps(run, indent=2))
    else:
        for r in store.list_runs(args.limit):
            print(f"{r['id']:4} {r['created_at']} {r['proposer']:10} {r['source_name'][:30]:30} {r['summary']}")
    return 0


def cmd_check_config(args: argparse.Namespace) -> int:
    s = load_settings()
    print(f"GEMINI_MODEL       = {s.gemini_model}")
    print(f"GEMINI_API_KEY     = {'set' if s.gemini_configured else 'NOT SET'}")
    print(f"timeout/retries    = {s.gemini_timeout_s}s / {s.gemini_max_retries}")
    print(f"max LLM calls/run  = {s.max_llm_calls}, attempts/finding = {s.max_attempts}")
    print(f"audit database     = {s.db_path}")
    print(f"redaction          = {'on' if s.redact else 'OFF'}")
    if args.live:
        from .llm import GeminiProposer, ProposalRequest
        m = load_manifest(_MINI)
        f = next(x for x in scan(m) if x.control_id == "PG002")
        prop = GeminiProposer(s).propose(ProposalRequest(m.resources[f.resource_index].obj, f))
        print(f"live call: {'OK' if prop.patch else 'FAILED'} ({prop.latency_ms:.0f} ms) {prop.error or ''}")
        return 0 if prop.patch else 1
    return 0


_MINI = "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n  containers: [{name: c, image: 'busybox:1.36'}]\n"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="patchgate", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="detect misconfigurations")
    s.add_argument("file")
    s.add_argument("--format", choices=["table", "json"], default="table")
    s.add_argument("--fail-on", choices=["low", "medium", "high"], help="exit 1 if a finding at or above this severity exists")
    s.set_defaults(func=cmd_scan)
    r = sub.add_parser("repair", help="propose, verify and apply repairs")
    r.add_argument("file")
    r.add_argument("--proposer", choices=["gemini", "template", "simulated"], default="template")
    r.add_argument("--out", help="write repaired manifest here (never overwrites the input)")
    r.add_argument("--report", help="write the full JSON report here")
    r.add_argument("--max-attempts", type=int, choices=range(1, 7), metavar="1-6")
    r.add_argument("--no-fallback", action="store_true", help="do not fall back to template fixes")
    r.add_argument("--no-audit", action="store_true", help="do not write the SQLite audit record")
    r.set_defaults(func=cmd_repair)
    v = sub.add_parser("verify", help="run the gate on an externally produced JSON Patch")
    v.add_argument("file")
    v.add_argument("--resource", type=int, required=True, help="0-based resource index in the file")
    v.add_argument("--control", required=True, choices=sorted(CONTROLS))
    v.add_argument("--subject", required=True, help="container name, 'pod', or 'volume:<name>'")
    v.add_argument("--patch", required=True, help="path to a JSON Patch file")
    v.add_argument("--gate", choices=sorted(GATES), default="patchgate")
    v.add_argument("--compare", action="store_true", help="show the verdict of every gate configuration")
    v.set_defaults(func=cmd_verify)
    ru = sub.add_parser("runs", help="list audit records")
    ru.add_argument("--id", type=int)
    ru.add_argument("--limit", type=int, default=20)
    ru.set_defaults(func=cmd_runs)
    c = sub.add_parser("check-config", help="validate configuration")
    c.add_argument("--live", action="store_true", help="make one real Gemini call (costs one request)")
    c.set_defaults(func=cmd_check_config)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (ManifestError, ConfigError, LLMUnavailable, BudgetExceeded) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"error: patch file is not valid JSON: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
