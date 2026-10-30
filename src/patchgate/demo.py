"""Offline demonstration script for the ``simulated`` proposer.

These candidates are HAND-WRITTEN imitations of mistakes LLM-generated configuration edits commonly
make (over-broad rewrites, string booleans, collateral image bumps, probes on undeclared ports,
limits below requests). They are not Gemini output and are always labelled ``simulated``. Their only
purpose is to show, without an API key, how the gate rejects a bad candidate, feeds the reasons
back, and accepts a corrected one.
"""
from __future__ import annotations

from typing import Any

DEMO_SCRIPT: dict[str, list[dict[str, Any]]] = {
    "PG001": [{"patch": "@template", "rationale": "Disable privileged mode."}],
    "PG002": [
        {"patch": [{"op": "add", "path": "{ctr}/securityContext", "value": {"allowPrivilegeEscalation": False}}],
         "rationale": "Rewrite the securityContext with privilege escalation disabled (over-broad: drops existing fields)."},
        {"patch": "@template", "rationale": "Set only allowPrivilegeEscalation=false."},
    ],
    "PG003": [
        {"patch": [{"op": "add", "path": "{ctr}/securityContext/runAsNonRoot", "value": "true"}],
         "rationale": "Require a non-root user (string instead of boolean)."},
        {"patch": "@template", "rationale": "runAsNonRoot=true and a non-zero UID.",
         "runtime_assumptions": ["image can run as UID 10001"]},
    ],
    "PG004": [{"patch": "@template", "rationale": "Stop sharing host namespaces."}],
    "PG005": [{"patch": "@template", "rationale": "Drop all capabilities."}],
    "PG006": [
        {"patch": [{"op": "add", "path": "{ctr}/securityContext/readOnlyRootFilesystem", "value": True},
                   {"op": "replace", "path": "{ctr}/image", "value": "nginx:1.27-alpine"}],
         "rationale": "Make the root filesystem read-only and move to the alpine image (collateral image change)."},
        {"patch": "@template", "rationale": "Make the root filesystem read-only."},
    ],
    "PG007": [
        {"patch": [{"op": "add", "path": "{ctr}/resources/limits", "value": {"cpu": "100m", "memory": "64Mi"}}],
         "rationale": "Add conservative limits (below the existing requests)."},
        {"patch": "@template", "rationale": "Limits equal to requests."},
    ],
    "PG010": [{"patch": "@template", "rationale": "Use the runtime default seccomp profile."}],
    "PG011": [
        {"patch": [{"op": "add", "path": "{ctr}/readinessProbe", "value": {"httpGet": {"path": "/healthz", "port": 8081}}}],
         "rationale": "HTTP readiness probe (on a port the container does not declare)."},
        {"patch": "@template", "rationale": "TCP readiness probe on the declared container port."},
    ],
}


def load_demo_script() -> dict[str, list[dict[str, Any]]]:
    return DEMO_SCRIPT
