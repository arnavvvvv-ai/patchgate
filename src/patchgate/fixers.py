"""Deterministic, template-based fixes (the approach of rule-based tools such as `kubescape fix`).

They serve two roles: a fallback proposer when Gemini is unavailable or fails, and the reference
"correct" candidates in the evaluation corpus. Every template fix still has to pass the gate.
"""
from __future__ import annotations

from typing import Any

from .checks import ALLOWED_ADD_CAPS, Finding
from .manifest import get_at, join_pointer, split_pointer

DEFAULT_LIMITS = {"cpu": "500m", "memory": "512Mi"}
NON_ROOT_UID = 10001


def set_ops(doc: dict[str, Any], pointer: str, value: Any) -> list[dict[str, Any]]:
    """Minimal ops that make ``doc[pointer] == value``, creating missing parent objects in one 'add'."""
    tokens = split_pointer(pointer)
    cur: Any = doc
    for i, tok in enumerate(tokens):
        if isinstance(cur, dict) and tok in cur:
            if i == len(tokens) - 1:
                return [] if cur[tok] == value else [{"op": "replace", "path": pointer, "value": value}]
            cur = cur[tok]
            continue
        if isinstance(cur, list) and tok.isdigit() and int(tok) < len(cur):
            if i == len(tokens) - 1:
                return [] if cur[int(tok)] == value else [{"op": "replace", "path": pointer, "value": value}]
            cur = cur[int(tok)]
            continue
        nested: Any = value
        for t in reversed(tokens[i + 1:]):
            nested = {t: nested}
        return [{"op": "add", "path": join_pointer(tokens[: i + 1]), "value": nested}]
    return []


def template_fix(resource: dict[str, Any], finding: Finding) -> list[dict[str, Any]] | None:
    """Return a JSON Patch for ``finding`` or None when no safe template exists (manual decision)."""
    cp = finding.container_pointer
    sc = f"{cp}/securityContext" if cp else None
    cid = finding.control_id
    if cid == "PG001":
        return set_ops(resource, f"{sc}/privileged", False)
    if cid == "PG002":
        return set_ops(resource, f"{sc}/allowPrivilegeEscalation", False)
    if cid == "PG003":
        ops = set_ops(resource, f"{sc}/runAsNonRoot", True)
        container = get_at(resource, cp) or {}
        pod_sc = get_at(resource, f"{finding.pod_prefix}/securityContext") or {}
        ctr_uid = (container.get("securityContext") or {}).get("runAsUser")
        if ctr_uid == 0 or (ctr_uid is None and pod_sc.get("runAsUser") == 0):
            tmp = _apply_preview(resource, ops)
            ops += set_ops(tmp, f"{sc}/runAsUser", NON_ROOT_UID)
        return ops
    if cid == "PG004":
        spec = get_at(resource, finding.pod_prefix) or {}
        return [{"op": "replace", "path": f"{finding.pod_prefix}/{k}", "value": False}
                for k in ("hostNetwork", "hostPID", "hostIPC") if spec.get(k) is True]
    if cid == "PG005":
        caps = get_at(resource, f"{sc}/capabilities") or {}
        add = [a for a in (caps.get("add") or []) if a in ALLOWED_ADD_CAPS]
        new_caps: dict[str, Any] = {"drop": ["ALL"]}
        if add:
            new_caps["add"] = add
        if isinstance(caps.get("drop"), list) and "ALL" not in caps["drop"] and not caps.get("add"):
            return [{"op": "add", "path": f"{sc}/capabilities/drop/-", "value": "ALL"}]
        return set_ops(resource, f"{sc}/capabilities", new_caps)
    if cid == "PG006":
        return set_ops(resource, f"{sc}/readOnlyRootFilesystem", True)
    if cid == "PG007":
        container = get_at(resource, cp) or {}
        requests = ((container.get("resources") or {}).get("requests") or {})
        limits = ((container.get("resources") or {}).get("limits") or {})
        ops: list[dict[str, Any]] = []
        tmp = resource
        for k in ("cpu", "memory"):
            if k not in limits:
                new = set_ops(tmp, f"{cp}/resources/limits/{k}", requests.get(k, DEFAULT_LIMITS[k]))
                ops += new
                tmp = _apply_preview(tmp, new)
        return ops
    if cid == "PG010":
        return set_ops(resource, f"{sc}/seccompProfile", {"type": "RuntimeDefault"})
    if cid == "PG011":
        container = get_at(resource, cp) or {}
        ports = [p for p in (container.get("ports") or []) if isinstance(p, dict) and "containerPort" in p]
        if not ports:
            return None
        return [{"op": "add", "path": f"{cp}/readinessProbe",
                 "value": {"tcpSocket": {"port": ports[0]["containerPort"]}, "initialDelaySeconds": 5, "periodSeconds": 10}}]
    return None  # PG008, PG009: behaviour-changing, escalate to a human


def _apply_preview(resource: dict[str, Any], ops: list[dict[str, Any]]) -> dict[str, Any]:
    from .patch import apply_patch, parse_patch
    return apply_patch(resource, parse_patch(ops)) if ops else resource
