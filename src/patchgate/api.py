"""FastAPI service so CI jobs or other tools can scan manifests and verify patches over HTTP.

Intended to run on localhost (``uvicorn patchgate.api:app --host 127.0.0.1``). It stores no manifests,
only audit metadata, and has no user accounts; do not expose it on a public interface.
"""
from __future__ import annotations

from typing import Any, Literal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from . import __version__
from .checks import CONTROLS, find_matching, scan
from .config import ConfigError, load_settings
from .llm import make_proposer
from .manifest import MAX_MANIFEST_BYTES, ManifestError, load_manifest
from .repair import repair_manifest
from .store import AuditStore
from .verifier import GATES, verify

app = FastAPI(title="PatchGate", version=__version__,
              description="Verified, behaviour-preserving repair of Kubernetes manifest misconfigurations")


class ManifestIn(BaseModel):
    manifest: str = Field(min_length=1, max_length=MAX_MANIFEST_BYTES)


class VerifyIn(ManifestIn):
    resource_index: int = Field(ge=0)
    control_id: str
    subject: str = Field(max_length=256)
    patch: list[dict[str, Any]] = Field(min_length=1, max_length=40)
    gate: str = "patchgate"
    compare: bool = False


class RepairIn(ManifestIn):
    proposer: Literal["template", "simulated", "gemini"] = "template"
    max_attempts: int = Field(default=3, ge=1, le=6)
    fallback_to_template: bool = True
    source_name: str = Field(default="api-upload", max_length=200)


def _load(text: str):
    try:
        return load_manifest(text)
    except ManifestError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _store() -> AuditStore:
    return AuditStore(load_settings().db_path)


@app.get("/health")
def health() -> dict[str, Any]:
    s = load_settings()
    return {"status": "ok", "version": __version__, "gemini_configured": s.gemini_configured, "model": s.gemini_model}


@app.get("/controls")
def controls() -> list[dict[str, Any]]:
    return [{"id": c.id, "title": c.title, "severity": c.severity, "category": c.category, "rationale": c.rationale,
             "auto_repairable": c.auto_repairable, "scope": list(c.scope), "runtime_assumptions": list(c.runtime_assumptions)}
            for c in CONTROLS.values()]


@app.post("/scan")
def scan_endpoint(body: ManifestIn) -> dict[str, Any]:
    m = _load(body.manifest)
    findings = [f.to_dict() for f in scan(m)]
    return {"resources": [r.ref for r in m.resources], "findings": findings}


@app.post("/verify")
def verify_endpoint(body: VerifyIn) -> dict[str, Any]:
    if body.gate not in GATES:
        raise HTTPException(status_code=422, detail=f"unknown gate {body.gate!r}; choose one of {sorted(GATES)}")
    m = _load(body.manifest)
    if body.resource_index >= len(m.resources):
        raise HTTPException(status_code=422, detail="resource_index out of range")
    finding = find_matching(scan(m), (body.control_id, body.resource_index, body.subject))
    if finding is None:
        raise HTTPException(status_code=404, detail="no such finding in this manifest")
    gates = list(GATES) if body.compare else [body.gate]
    out = {}
    for g in gates:
        verdict, _ = verify(m.resources[body.resource_index].obj, finding, body.patch, GATES[g])
        out[g] = {**verdict.model_dump(), "reasons": verdict.reasons}
    return {"finding": finding.to_dict(), "verdicts": out}


@app.post("/repair")
def repair_endpoint(body: RepairIn) -> dict[str, Any]:
    settings = load_settings()
    m = _load(body.manifest)
    try:
        proposer = make_proposer(body.proposer, settings)
    except ConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    report = repair_manifest(m, proposer, max_attempts=body.max_attempts,
                             fallback_to_template=body.fallback_to_template, source_text=body.manifest)
    run_id = AuditStore(settings.db_path).record(report, body.source_name,
                                                 settings.gemini_model if body.proposer == "gemini" else None)
    return {"run_id": run_id, "simulated": body.proposer == "simulated", **report.to_dict()}


@app.get("/runs")
def runs(limit: int = 50) -> list[dict[str, Any]]:
    return _store().list_runs(limit)


@app.get("/runs/{run_id}")
def run(run_id: int) -> dict[str, Any]:
    r = _store().get_run(run_id)
    if r is None:
        raise HTTPException(status_code=404, detail="run not found")
    return r
