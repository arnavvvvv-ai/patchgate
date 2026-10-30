"""Verifier-guided repair loop: propose -> verify -> (feed counterexamples back) -> accept or escalate."""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any

from .checks import CONTROLS, Finding, find_matching, scan, scan_resource
from .fixers import template_fix
from .llm import BudgetExceeded, LLMUnavailable, Proposal, Proposer, ProposalRequest
from .manifest import Manifest, dump_documents
from .verifier import GATES, GateConfig, verify

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


@dataclass
class AttemptRecord:
    attempt: int
    proposer: str
    simulated: bool
    patch: list[dict[str, Any]] | None
    accepted: bool
    reasons: list[str]
    checks: list[dict[str, Any]]
    rationale: str = ""
    runtime_assumptions: list[str] = field(default_factory=list)
    error: str | None = None
    latency_ms: float = 0.0


@dataclass
class FindingOutcome:
    finding: dict[str, Any]
    status: str  # repaired | manual | unrepaired | resolved-by-other
    attempts: list[AttemptRecord] = field(default_factory=list)
    accepted_patch: list[dict[str, Any]] | None = None
    accepted_by: str | None = None
    runtime_assumptions: list[str] = field(default_factory=list)


@dataclass
class RepairReport:
    proposer: str
    source_sha256: str
    outcomes: list[FindingOutcome]
    findings_before: list[dict[str, Any]]
    findings_after: list[dict[str, Any]]
    repaired_yaml: str
    patches: dict[str, list[dict[str, Any]]]
    llm_calls: int = 0
    degraded: str | None = None

    @property
    def summary(self) -> dict[str, int]:
        s: dict[str, int] = {"findings_before": len(self.findings_before), "findings_after": len(self.findings_after)}
        for o in self.outcomes:
            s[o.status] = s.get(o.status, 0) + 1
        s["rejected_candidates"] = sum(1 for o in self.outcomes for a in o.attempts if a.patch is not None and not a.accepted)
        return s

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["summary"] = self.summary
        return d


def _order(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(CONTROLS[f.control_id].severity, 9), f.control_id, f.subject))


def _record(attempt: int, p: Proposal, verdict: Any) -> AttemptRecord:
    return AttemptRecord(
        attempt=attempt, proposer=p.source, simulated=p.simulated, patch=p.patch,
        accepted=bool(verdict and verdict.accepted), reasons=(verdict.reasons if verdict else ([p.error] if p.error else [])),
        checks=[c.model_dump() for c in verdict.checks] if verdict else [],
        rationale=p.rationale, runtime_assumptions=p.runtime_assumptions, error=p.error, latency_ms=p.latency_ms,
    )


def repair_manifest(manifest: Manifest, proposer: Proposer, *, max_attempts: int = 3, fallback_to_template: bool = True,
                    gate: GateConfig = GATES["patchgate"], source_text: str = "") -> RepairReport:
    work = manifest.clone()
    before = scan(work)
    outcomes: list[FindingOutcome] = []
    patches: dict[str, list[dict[str, Any]]] = {}
    degraded: str | None = None

    for res in work.workloads():
        for original in _order(scan_resource(res)):
            finding = find_matching(scan_resource(res), original.key)
            if finding is None:
                outcomes.append(FindingOutcome(original.to_dict(), "resolved-by-other"))
                continue
            outcome = FindingOutcome(finding.to_dict(), "unrepaired")
            outcomes.append(outcome)
            if not CONTROLS[finding.control_id].auto_repairable:
                outcome.status = "manual"
                continue
            feedback: list[str] = []
            accepted_after: dict[str, Any] | None = None
            if degraded is None:
                for attempt in range(1, max_attempts + 1):
                    try:
                        prop = proposer.propose(ProposalRequest(res.obj, finding, attempt, feedback))
                    except (LLMUnavailable, BudgetExceeded) as exc:
                        degraded = str(exc)
                        outcome.attempts.append(AttemptRecord(attempt, proposer.name, False, None, False, [str(exc)], [], error=str(exc)))
                        break
                    if prop.patch is None:
                        outcome.attempts.append(_record(attempt, prop, None))
                        if prop.source == "template" or "no more" in (prop.error or ""):
                            break
                        feedback = [prop.error or "no patch produced"]
                        continue
                    verdict, after = verify(res.obj, finding, prop.patch, gate)
                    outcome.attempts.append(_record(attempt, prop, verdict))
                    if verdict.accepted and after is not None:
                        accepted_after = after
                        outcome.accepted_by = prop.source
                        outcome.accepted_patch = prop.patch
                        outcome.runtime_assumptions = sorted(set(prop.runtime_assumptions) | set(CONTROLS[finding.control_id].runtime_assumptions))
                        break
                    feedback = verdict.reasons
            if accepted_after is None and fallback_to_template and proposer.name != "template":
                patch = template_fix(res.obj, finding)
                if patch:
                    prop = Proposal("template-fallback", patch, rationale="deterministic template fallback",
                                    runtime_assumptions=list(CONTROLS[finding.control_id].runtime_assumptions))
                    verdict, after = verify(res.obj, finding, patch, gate)
                    outcome.attempts.append(_record(len(outcome.attempts) + 1, prop, verdict))
                    if verdict.accepted and after is not None:
                        accepted_after = after
                        outcome.accepted_by = "template-fallback"
                        outcome.accepted_patch = patch
                        outcome.runtime_assumptions = list(prop.runtime_assumptions)
            if accepted_after is not None:
                res.obj = accepted_after
                outcome.status = "repaired"
                patches.setdefault(f"{res.index}:{res.ref}", []).extend(outcome.accepted_patch or [])

    after_findings = scan(work)
    budget = getattr(proposer, "budget", None)
    return RepairReport(
        proposer=proposer.name,
        source_sha256=hashlib.sha256(source_text.encode("utf-8")).hexdigest() if source_text else "",
        outcomes=outcomes,
        findings_before=[f.to_dict() for f in before],
        findings_after=[f.to_dict() for f in after_findings],
        repaired_yaml=dump_documents([r.obj for r in work.resources]),
        patches=patches,
        llm_calls=getattr(budget, "used", 0),
        degraded=degraded,
    )
