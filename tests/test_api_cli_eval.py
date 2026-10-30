import json

import pytest
from fastapi.testclient import TestClient

from evaluation.corpus import build_corpus
from evaluation.run_eval import evaluate
from patchgate.api import app
from patchgate.cli import main

from .conftest import CTR0, EXAMPLES

client = TestClient(app)


def test_health_and_controls():
    h = client.get("/health").json()
    assert h["status"] == "ok" and h["gemini_configured"] is False
    ids = [c["id"] for c in client.get("/controls").json()]
    assert ids[0] == "PG001" and "PG011" in ids


def test_scan_endpoint(deployment_text):
    r = client.post("/scan", json={"manifest": deployment_text})
    assert r.status_code == 200 and any(f["control_id"] == "PG002" for f in r.json()["findings"])
    assert client.post("/scan", json={"manifest": "a: [1"}).status_code == 422
    assert client.post("/scan", json={"manifest": ""}).status_code == 422


def test_verify_endpoint_compare(deployment_text):
    body = {"manifest": deployment_text, "resource_index": 0, "control_id": "PG002", "subject": "api", "compare": True,
            "patch": [{"op": "replace", "path": f"{CTR0}/securityContext", "value": {"allowPrivilegeEscalation": False}}]}
    v = client.post("/verify", json=body).json()["verdicts"]
    assert v["relint-full"]["accepted"] is True and v["patchgate"]["accepted"] is False
    assert any("scope" in r for r in v["patchgate"]["reasons"])
    assert client.post("/verify", json={**body, "subject": "nobody"}).status_code == 404
    assert client.post("/verify", json={**body, "gate": "nope"}).status_code == 422


def test_repair_endpoint_and_runs(deployment_text):
    r = client.post("/repair", json={"manifest": deployment_text, "proposer": "simulated"})
    assert r.status_code == 200
    data = r.json()
    assert data["simulated"] is True and data["summary"]["repaired"] >= 1
    runs = client.get("/runs").json()
    assert runs[0]["id"] == data["run_id"]
    assert client.get(f"/runs/{data['run_id']}").json()["attempts"]
    assert client.get("/runs/424242").status_code == 404


def test_repair_endpoint_gemini_without_key_is_400(deployment_text):
    r = client.post("/repair", json={"manifest": deployment_text, "proposer": "gemini"})
    assert r.status_code == 400 and "GEMINI_API_KEY" in r.json()["detail"]


def test_cli_scan_exit_codes(capsys):
    f = str(EXAMPLES / "node-agent.yaml")
    assert main(["scan", f]) == 0
    assert main(["scan", f, "--fail-on", "high"]) == 1
    capsys.readouterr()
    assert main(["scan", f, "--format", "json"]) == 0
    findings = json.loads(capsys.readouterr().out)
    assert {x["control_id"] for x in findings} >= {"PG001", "PG004", "PG008"}


def test_cli_repair_writes_outputs(tmp_path, capsys):
    out, rep = tmp_path / "fixed.yaml", tmp_path / "report.json"
    src = str(EXAMPLES / "web-app.yaml")
    assert main(["repair", src, "--proposer", "simulated", "--out", str(out), "--report", str(rep)]) == 0
    text = capsys.readouterr().out
    assert "REJECT" in text and "ACCEPT" in text and "simulated" in text
    assert "readOnlyRootFilesystem: true" in out.read_text(encoding="utf-8")
    assert json.loads(rep.read_text(encoding="utf-8"))["summary"]["manual"] == 1
    with pytest.raises(SystemExit, match="refusing"):
        main(["repair", src, "--out", src, "--no-audit"])


def test_cli_verify_and_errors(tmp_path):
    patch = tmp_path / "p.json"
    patch.write_text(json.dumps([{"op": "add", "path": "/spec/jobTemplate/spec/template/spec/containers/0/securityContext",
                                  "value": {"allowPrivilegeEscalation": False}}]), encoding="utf-8")
    src = str(EXAMPLES / "nightly-report.yaml")
    assert main(["verify", src, "--resource", "0", "--control", "PG002", "--subject", "report", "--patch", str(patch), "--compare"]) == 0
    bad = tmp_path / "bad.yaml"
    bad.write_text("a: [1", encoding="utf-8")
    assert main(["scan", str(bad)]) == 2
    assert main(["repair", src, "--proposer", "gemini", "--no-audit"]) == 2  # no key -> actionable config error


def test_cli_live_check_reports_gemini_error_without_traceback(monkeypatch, capsys):
    import patchgate.llm as llm
    monkeypatch.setenv("GEMINI_API_KEY", "AIza-test-not-real")
    def boom(self, prompt):
        raise llm.LLMUnavailable("Gemini rejected the request (404): model not available")
    monkeypatch.setattr(llm.GeminiProposer, "_generate", boom)
    assert main(["check-config", "--live"]) == 2
    assert "404" in capsys.readouterr().err


def test_evaluation_corpus_is_deterministic_and_labelled():
    a, b = build_corpus(11, 15), build_corpus(11, 15)
    assert [c.case_id for c in a] == [c.case_id for c in b]
    assert {c.valid for c in a} == {True, False}
    res = evaluate(a)
    m = res["metrics"]
    assert m["apply-only"]["valid_total"] == res["counts"]["valid"]
    assert m["relint-full"]["false_accept_rate"] >= m["patchgate"]["false_accept_rate"]
    for g in m.values():
        assert g["invalid_accepted"] + (g["invalid_total"] - g["invalid_accepted"]) == res["counts"]["invalid"]
