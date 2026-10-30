from patchgate.checks import scan
from patchgate.demo import DEMO_SCRIPT
from patchgate.llm import LLMUnavailable, Proposal, ScriptedProposer, TemplateProposer
from patchgate.manifest import load_manifest
from patchgate.repair import repair_manifest
from patchgate.store import AuditStore

from .conftest import CTR0, EXAMPLES


class RecordingProposer:
    """Bad candidate first, then the correct one; records the feedback it was given."""

    name = "recording"

    def __init__(self):
        self.feedback = []

    def propose(self, req):
        self.feedback.append(list(req.feedback))
        if req.attempt == 1:
            return Proposal(self.name, [{"op": "replace", "path": f"{req.finding.container_pointer}/securityContext",
                                         "value": {"allowPrivilegeEscalation": False}}])
        return Proposal(self.name, [{"op": "add", "path": f"{req.finding.container_pointer}/securityContext/allowPrivilegeEscalation",
                                     "value": False}])


class DownProposer:
    name = "gemini"

    def __init__(self):
        self.calls = 0

    def propose(self, req):
        self.calls += 1
        raise LLMUnavailable("service down")


def test_feedback_loop_rejects_then_accepts(deployment_text):
    m = load_manifest(deployment_text)
    only_pg002 = RecordingProposer()
    report = repair_manifest(m, only_pg002, max_attempts=3, fallback_to_template=False)
    o = next(x for x in report.outcomes if x.finding["control_id"] == "PG002" and x.finding["subject"] == "api")
    assert o.status == "repaired" and o.accepted_by == "recording"
    assert [a.accepted for a in o.attempts] == [False, True]
    assert any("scope" in r for r in only_pg002.feedback[1])
    repaired = load_manifest(report.repaired_yaml).resources[0].obj
    assert repaired["spec"]["template"]["spec"]["containers"][0]["securityContext"]["runAsUser"] == 1000


def test_input_manifest_never_mutated(deployment_text):
    m = load_manifest(deployment_text)
    snapshot = m.to_yaml()
    repair_manifest(m, TemplateProposer())
    assert m.to_yaml() == snapshot


def test_outage_degrades_to_template_fallback(deployment_text):
    down = DownProposer()
    report = repair_manifest(load_manifest(deployment_text), down)
    assert report.degraded and "service down" in report.degraded
    assert down.calls == 1  # stops calling a dead service
    assert all(o.status in ("repaired", "manual") for o in report.outcomes if o.status != "resolved-by-other")
    assert any(o.accepted_by == "template-fallback" for o in report.outcomes)


def test_no_fallback_leaves_unrepaired(deployment_text):
    report = repair_manifest(load_manifest(deployment_text), DownProposer(), fallback_to_template=False)
    assert report.summary.get("repaired", 0) == 0 and report.summary["unrepaired"] >= 1
    assert report.findings_after == report.findings_before


def test_demo_examples_end_state():
    for name in ("web-app.yaml", "node-agent.yaml", "nightly-report.yaml"):
        m = load_manifest((EXAMPLES / name).read_text(encoding="utf-8"))
        report = repair_manifest(m, ScriptedProposer(DEMO_SCRIPT))
        remaining = {f["control_id"] for f in report.findings_after}
        assert remaining <= {"PG008", "PG009"}, (name, remaining)  # only the manual ones remain
        assert report.summary["rejected_candidates"] >= 1
        # Service and other non-workload docs are preserved
        assert len(load_manifest(report.repaired_yaml).resources) == len(m.resources)
        assert all(a.simulated for o in report.outcomes for a in o.attempts if a.proposer == "simulated")


def test_applying_reported_patches_reproduces_output(deployment_text):
    from patchgate.patch import apply_patch, parse_patch
    m = load_manifest(deployment_text)
    report = repair_manifest(m, TemplateProposer())
    patched = apply_patch(m.resources[0].obj, parse_patch(report.patches["0:Deployment/api"]))
    assert patched == load_manifest(report.repaired_yaml).resources[0].obj
    assert all(not f.control.auto_repairable for f in scan(load_manifest(report.repaired_yaml)))


def test_audit_store_roundtrip(tmp_path, deployment_text):
    store = AuditStore(tmp_path / "a.db")
    report = repair_manifest(load_manifest(deployment_text), ScriptedProposer(DEMO_SCRIPT), source_text=deployment_text)
    run_id = store.record(report, "deploy.yaml")
    runs = store.list_runs()
    assert runs[0]["id"] == run_id and runs[0]["summary"]["repaired"] >= 1
    run = store.get_run(run_id)
    assert run["source_sha256"] == report.source_sha256 and len(run["source_sha256"]) == 64
    assert any(a["accepted"] == 0 and a["patch"] for a in run["attempts"])
    raw = (tmp_path / "a.db").read_bytes()
    assert b"s3cr3t-value" not in raw  # manifest contents are not persisted
    assert store.get_run(999) is None
    assert AuditStore(tmp_path / "a.db").list_runs()[0]["id"] == run_id  # survives reopen
    assert CTR0
