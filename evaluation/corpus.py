"""Seeded generator for the gate-discrimination benchmark.

1. Generate random but realistic workloads (6 kinds, 1-3 containers, ports, env, volumes, partial
   security contexts) with injected misconfigurations.
2. For every auto-repairable finding, build candidate patches with a ground-truth label:
   * VALID   - the template fix plus independently written alternative correct fixes;
   * INVALID - candidates produced by mutation operators modelling documented failure modes of
               automated/LLM configuration edits (see docs/EVALUATION.md for the taxonomy).

Labels are assigned by construction, not by any gate. Operators only fire when their precondition
guarantees the mutation is genuinely harmful (e.g. 'over-broad rewrite' only when it deletes
existing settings).
"""
from __future__ import annotations

import copy
import json
import random
from dataclasses import dataclass, field
from typing import Any, Callable

from patchgate.checks import CONTROLS, Finding, scan_object
from patchgate.fixers import set_ops, template_fix
from patchgate.manifest import get_at
from patchgate.patch import PatchError, apply_patch, parse_patch

KINDS = ["Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod"]
IMAGES = ["nginx:1.27", "redis:7.2", "postgres:16.3", "python:3.12-slim", "ghcr.io/acme/api:2.4.1",
          "registry.k8s.io/pause:3.9", "busybox:1.36", "node:20-alpine", "grafana/grafana:11.1.0"]
NAMES = ["app", "web", "worker", "sidecar", "proxy", "metrics", "cache", "api"]
ENV_NAMES = ["LOG_LEVEL", "PORT", "DB_HOST", "FEATURE_FLAGS", "REGION"]


@dataclass
class Candidate:
    case_id: str
    resource: dict[str, Any]
    finding: Finding
    patch: list[dict[str, Any]]
    valid: bool
    category: str
    note: str = ""

    def to_json(self) -> dict[str, Any]:
        return {"case_id": self.case_id, "control_id": self.finding.control_id, "subject": self.finding.subject,
                "kind": self.resource.get("kind"), "valid": self.valid, "category": self.category,
                "note": self.note, "patch": self.patch}


# ---------------------------------------------------------------- workload generator

def _container(rng: random.Random, name: str) -> dict[str, Any]:
    c: dict[str, Any] = {"name": name, "image": rng.choice(IMAGES)}
    if rng.random() < 0.3:
        c["args"] = ["--verbose"] if rng.random() < 0.5 else ["serve", "--port", "8080"]
    if rng.random() < 0.65:
        c["ports"] = [{"name": "http", "containerPort": rng.choice([80, 8080, 3000, 9090])}]
        if rng.random() < 0.3:
            c["ports"].append({"name": "metrics", "containerPort": 9100})
    if rng.random() < 0.6:
        c["env"] = [{"name": n, "value": str(rng.randint(1, 99))} for n in rng.sample(ENV_NAMES, rng.randint(1, 3))]
    res: dict[str, Any] = {}
    if rng.random() < 0.6:
        res["requests"] = {"cpu": rng.choice(["100m", "250m", "500m"]), "memory": rng.choice(["128Mi", "256Mi", "1Gi"])}
    if rng.random() < 0.35:
        res["limits"] = {"cpu": "1", "memory": "2Gi"} if rng.random() < 0.7 else {"memory": "2Gi"}
    if res:
        c["resources"] = res
    sc: dict[str, Any] = {}
    r = rng.random
    if r() < 0.12:
        sc["privileged"] = True
    if r() < 0.4:
        sc["allowPrivilegeEscalation"] = r() < 0.4
    if r() < 0.35:
        sc["runAsUser"] = rng.choice([0, 1000, 10001])
    if r() < 0.3:
        sc["runAsNonRoot"] = True
    if r() < 0.4:
        caps: dict[str, Any] = {}
        if r() < 0.7:
            caps["drop"] = ["ALL"] if r() < 0.7 else ["NET_RAW"]
        if r() < 0.35:
            caps["add"] = rng.sample(["NET_BIND_SERVICE", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"], rng.randint(1, 2))
        if caps:
            sc["capabilities"] = caps
    if r() < 0.35:
        sc["readOnlyRootFilesystem"] = r() < 0.6
    if r() < 0.25:
        sc["seccompProfile"] = {"type": "RuntimeDefault"}
    if sc:
        c["securityContext"] = sc
    if c.get("ports") and r() < 0.3:
        c["readinessProbe"] = {"tcpSocket": {"port": c["ports"][0]["containerPort"]}}
    return c


def generate_workload(rng: random.Random, idx: int) -> dict[str, Any]:
    kind = rng.choice(KINDS)
    app = f"svc-{idx}"
    names = rng.sample(NAMES, rng.choice([1, 1, 2, 2, 3]))
    spec: dict[str, Any] = {"containers": [_container(rng, n) for n in names]}
    if rng.random() < 0.3:
        spec["securityContext"] = {k: v for k, v in {
            "runAsNonRoot": True if rng.random() < 0.6 else None,
            "runAsUser": rng.choice([0, 1000]) if rng.random() < 0.4 else None,
            "seccompProfile": {"type": "RuntimeDefault"} if rng.random() < 0.4 else None,
            "fsGroup": 2000 if rng.random() < 0.3 else None,
        }.items() if v is not None} or {"fsGroup": 2000}
    if rng.random() < 0.1:
        spec["hostNetwork"] = True
    if rng.random() < 0.05:
        spec["hostPID"] = True
    if rng.random() < 0.35:
        spec["serviceAccountName"] = f"{app}-sa"
    vols = []
    if rng.random() < 0.5:
        vols.append({"name": "data", "emptyDir": {}})
        spec["containers"][0]["volumeMounts"] = [{"name": "data", "mountPath": "/data"}]
    if rng.random() < 0.3:
        vols.append({"name": "config", "configMap": {"name": f"{app}-config"}})
        spec["containers"][0].setdefault("volumeMounts", []).append({"name": "config", "mountPath": "/etc/app", "readOnly": True})
    if rng.random() < 0.08:
        vols.append({"name": "host", "hostPath": {"path": "/var/run"}})
    if vols:
        spec["volumes"] = vols
    labels = {"app": app}
    template = {"metadata": {"labels": dict(labels)}, "spec": spec}
    meta = {"name": app, "namespace": rng.choice(["default", "prod", "staging"]), "labels": dict(labels)}
    if kind == "Pod":
        return {"apiVersion": "v1", "kind": "Pod", "metadata": meta, "spec": spec}
    if kind in ("Job", "CronJob"):
        spec["restartPolicy"] = "OnFailure"
        job = {"backoffLimit": 3, "template": template}
        if kind == "Job":
            return {"apiVersion": "batch/v1", "kind": "Job", "metadata": meta, "spec": job}
        return {"apiVersion": "batch/v1", "kind": "CronJob", "metadata": meta,
                "spec": {"schedule": f"{rng.randint(0, 59)} {rng.randint(0, 23)} * * *", "jobTemplate": {"spec": job}}}
    body: dict[str, Any] = {"selector": {"matchLabels": dict(labels)}, "template": template}
    if kind in ("Deployment", "StatefulSet"):
        body["replicas"] = rng.choice([1, 2, 3, 5])
    if kind == "StatefulSet":
        body["serviceName"] = app
    return {"apiVersion": "apps/v1", "kind": kind, "metadata": meta, "spec": body}


# ---------------------------------------------------------------- candidate construction

def _applies(resource: dict[str, Any], patch: list[dict[str, Any]]) -> dict[str, Any] | None:
    try:
        return apply_patch(resource, parse_patch(patch))
    except (PatchError, ValueError):
        return None


def _resolves(resource: dict[str, Any], finding: Finding, patch: list[dict[str, Any]]) -> bool:
    after = _applies(resource, patch)
    return after is not None and finding.key not in {f.key for f in scan_object(after, finding.resource_index)}


def _ctr(resource: dict[str, Any], finding: Finding) -> dict[str, Any]:
    return get_at(resource, finding.container_pointer) if finding.container_pointer else {}


def _then(resource: dict[str, Any], base: list[dict[str, Any]], extra_fn: Callable[[dict[str, Any]], list[dict[str, Any]]]) -> list[dict[str, Any]] | None:
    after = _applies(resource, base)
    if after is None:
        return None
    extra = extra_fn(after)
    return base + extra if extra else None


def valid_variants(res: dict[str, Any], f: Finding) -> list[tuple[str, list[dict[str, Any]]]]:
    out: list[tuple[str, list[dict[str, Any]]]] = []
    tmpl = template_fix(res, f)
    if tmpl:
        out.append(("template", tmpl))
    cp, pp, cid = f.container_pointer, f.pod_prefix, f.control_id
    sc = _ctr(res, f).get("securityContext") if cp else None
    if cid in ("PG001", "PG002", "PG006") and isinstance(sc, dict):
        key = {"PG001": "privileged", "PG002": "allowPrivilegeEscalation", "PG006": "readOnlyRootFilesystem"}[cid]
        val = cid == "PG006"
        out.append(("add-op-variant", [{"op": "add", "path": f"{cp}/securityContext/{key}", "value": val}]))
    if cid == "PG003":
        p = set_ops(res, f"{pp}/securityContext/runAsNonRoot", True)
        # Pod-level runAsNonRoot applies to every container: it is only a valid fix when no container in the pod
        # runs as UID 0, because the kubelet refuses to start a container that must be non-root but is set to UID 0.
        spec = get_at(res, pp) or {}
        pod_uid = (spec.get("securityContext") or {}).get("runAsUser")
        uids = [(c.get("securityContext") or {}).get("runAsUser", pod_uid)
                for g in ("initContainers", "containers") for c in (spec.get(g) or []) if isinstance(c, dict)]
        if p and 0 not in uids and _resolves(res, f, p):
            out.append(("pod-level-runAsNonRoot", p))
        if isinstance(sc, dict):
            first = set_ops(res, f"{cp}/securityContext/runAsUser", 1000)
            p2 = (_then(res, first, lambda a: set_ops(a, f"{cp}/securityContext/runAsNonRoot", True)) or first) if first \
                else set_ops(res, f"{cp}/securityContext/runAsNonRoot", True)
        else:
            p2 = [{"op": "add", "path": f"{cp}/securityContext", "value": {"runAsUser": 1000, "runAsNonRoot": True}}]
        if p2 and _resolves(res, f, p2):
            out.append(("explicit-uid", p2))
    if cid == "PG010":
        p = set_ops(res, f"{pp}/securityContext/seccompProfile", {"type": "RuntimeDefault"})
        if p and _resolves(res, f, p):
            out.append(("pod-level-seccomp", p))
    if cid == "PG007":
        req = ((_ctr(res, f).get("resources") or {}).get("requests") or {})
        lim = ((_ctr(res, f).get("resources") or {}).get("limits") or {})
        values = {"cpu": "2" if "cpu" in req else "1", "memory": "4Gi" if "memory" in req else "1Gi"}
        p: list[dict[str, Any]] = []
        cur = res
        for k in ("cpu", "memory"):
            if k not in lim:
                step = set_ops(cur, f"{cp}/resources/limits/{k}", values[k])
                p += step
                cur = _applies(cur, step) or cur
        if p:
            out.append(("generous-limits", p))
    if cid == "PG011":
        ports = _ctr(res, f).get("ports") or []
        named = [x for x in ports if x.get("name")]
        if named:
            out.append(("http-named-port", [{"op": "add", "path": f"{cp}/readinessProbe",
                                             "value": {"httpGet": {"path": "/", "port": named[0]["name"]}, "periodSeconds": 10}}]))
    if cid == "PG006" and tmpl:
        mounts = _ctr(res, f).get("volumeMounts") or []
        if not any(m.get("mountPath") == "/tmp" for m in mounts) and not any(
                v.get("name") == "tmp" for v in (get_at(res, f"{pp}/volumes") or [])):
            vol_op = ({"op": "add", "path": f"{pp}/volumes/-", "value": {"name": "tmp", "emptyDir": {}}}
                      if get_at(res, f"{pp}/volumes") is not None else
                      {"op": "add", "path": f"{pp}/volumes", "value": [{"name": "tmp", "emptyDir": {}}]})
            mnt_op = ({"op": "add", "path": f"{cp}/volumeMounts/-", "value": {"name": "tmp", "mountPath": "/tmp"}}
                      if mounts else {"op": "add", "path": f"{cp}/volumeMounts", "value": [{"name": "tmp", "mountPath": "/tmp"}]})
            out.append(("readonly-with-tmp-emptydir", tmpl + [vol_op, mnt_op]))
    return [(n, p) for n, p in out if _resolves(res, f, p)]


def invalid_mutants(res: dict[str, Any], f: Finding, rng: random.Random) -> list[tuple[str, list[dict[str, Any]], str]]:
    """(category, patch, note). Each operator fires only when its harm precondition holds."""
    out: list[tuple[str, list[dict[str, Any]], str]] = []
    tmpl = template_fix(res, f)
    if not tmpl:
        return out
    cp, pp, cid = f.container_pointer, f.pod_prefix, f.control_id
    spec = get_at(res, pp) or {}
    ctr = _ctr(res, f) if cp else {}
    containers = spec.get("containers") or []

    # M0 unapplicable: replace on a path that does not exist
    out.append(("unapplicable", [{"op": "replace", "path": f"{pp}/nonexistent/field", "value": True}], "path does not exist"))

    # M1 wrong-container: correct fix aimed at a different container
    if cp and cp.split("/")[-2] == "containers" and len(containers) > 1:
        idx = int(cp.split("/")[-1])
        other = f"{pp}/containers/{(idx + 1) % len(containers)}"
        wrong = template_fix(res, Finding(cid, f.resource_index, f.resource_ref, "x", other, pp, other, ""))
        if wrong and not _resolves(res, f, wrong):
            out.append(("wrong-container", wrong, "fix applied to the neighbouring container"))

    # M2 over-broad rewrite of securityContext that deletes existing settings
    if cp and isinstance(ctr.get("securityContext"), dict):
        after = _applies(res, tmpl)
        new_sc = (get_at(after, cp) or {}).get("securityContext") if after else None
        if isinstance(new_sc, dict):
            key_map = {"PG001": "privileged", "PG002": "allowPrivilegeEscalation", "PG003": "runAsNonRoot",
                       "PG005": "capabilities", "PG006": "readOnlyRootFilesystem", "PG010": "seccompProfile"}
            k = key_map.get(cid)
            if k and k in new_sc:
                minimal = {k: new_sc[k]}
                if cid == "PG003" and "runAsUser" in new_sc:
                    minimal["runAsUser"] = new_sc["runAsUser"]
                # removing a field is harmful unless it held the API default value
                defaults = {"privileged": False, "readOnlyRootFilesystem": False}
                dropped = {d for d in set(ctr["securityContext"]) - set(minimal)
                           if not (d in defaults and ctr["securityContext"][d] == defaults[d])}
                if dropped:
                    out.append(("over-broad-rewrite", [{"op": "replace", "path": f"{cp}/securityContext", "value": minimal}],
                                f"deletes existing securityContext fields {sorted(dropped)}"))

    # M3 collateral image change
    if cp and ":" in str(ctr.get("image", "")):
        repo, tag = str(ctr["image"]).rsplit(":", 1)
        out.append(("collateral-image-change", tmpl + [{"op": "replace", "path": f"{cp}/image", "value": f"{repo}:{tag}-patched"}],
                    "also bumps the image tag"))

    # M4 label/selector edit breaking Service/controller selection
    label_path = "/metadata/labels/app" if res.get("kind") == "Pod" else (
        "/spec/template/metadata/labels/app" if get_at(res, "/spec/template/metadata/labels/app") else
        "/spec/jobTemplate/spec/template/metadata/labels/app")
    if get_at(res, label_path) is not None:
        out.append(("label-selector-edit", tmpl + [{"op": "replace", "path": label_path, "value": f"{get_at(res, label_path)}-secure"}],
                    "renames the app label the selector/Service relies on"))

    # M5 container rewrite dropping configuration
    if cp and any(k in ctr for k in ("env", "ports", "volumeMounts", "args")):
        after = _applies(res, tmpl)
        fixed = get_at(after, cp) if after else None
        if isinstance(fixed, dict):
            slim = {k: v for k, v in fixed.items() if k not in ("env", "ports", "volumeMounts", "args")}
            if cid != "PG011":
                out.append(("container-rewrite", [{"op": "replace", "path": cp, "value": slim}],
                            "rewrites the container and drops env/ports/mounts/args"))

    # M6 string booleans (YAML 'yes'/'"false"' confusion)
    if cid in ("PG001", "PG002", "PG006", "PG004"):
        out.append(("string-boolean", json.loads(json.dumps(tmpl).replace("false", '"false"').replace("true", '"true"')),
                    "booleans encoded as strings"))

    # M7 removal-as-fix: delete the offending container or the thing that triggers the rule
    if cp and cp.split("/")[-2] == "containers" and len(containers) > 1:
        out.append(("delete-container", [{"op": "remove", "path": cp}], "removes the offending container"))
    if cid == "PG011" and ctr.get("ports"):
        out.append(("remove-ports", [{"op": "remove", "path": f"{cp}/ports"}], "removes ports so the probe rule no longer applies"))

    # M8 probe on an undeclared port
    if cid == "PG011":
        declared = {p.get("containerPort") for p in ctr.get("ports") or []}
        bad = next(p for p in (8081, 8443, 5000, 1234) if p not in declared)
        out.append(("probe-undeclared-port", [{"op": "add", "path": f"{cp}/readinessProbe", "value": {"httpGet": {"path": "/healthz", "port": bad}}}],
                    f"probe targets port {bad} which the container does not expose"))

    # M9 limits below requests
    if cid == "PG007":
        req = ((ctr.get("resources") or {}).get("requests") or {})
        lim = ((ctr.get("resources") or {}).get("limits") or {})
        low = {"cpu": "10m", "memory": "8Mi"}
        if any(k in req and k not in lim for k in low):
            p: list[dict[str, Any]] = []
            cur = res
            for k in ("cpu", "memory"):
                if k not in lim:
                    step = set_ops(cur, f"{cp}/resources/limits/{k}", low[k])
                    p += step
                    cur = _applies(cur, step) or cur
            out.append(("limits-below-requests", p, "limits lower than the existing requests"))

    # M10 hostPath scratch space for a read-only root filesystem
    if cid == "PG006":
        vols = get_at(res, f"{pp}/volumes")
        vol_op = ({"op": "add", "path": f"{pp}/volumes/-", "value": {"name": "scratch", "hostPath": {"path": "/tmp"}}}
                  if vols is not None else {"op": "add", "path": f"{pp}/volumes", "value": [{"name": "scratch", "hostPath": {"path": "/tmp"}}]})
        mounts = ctr.get("volumeMounts")
        mnt_op = ({"op": "add", "path": f"{cp}/volumeMounts/-", "value": {"name": "scratch", "mountPath": "/scratch"}}
                  if mounts else {"op": "add", "path": f"{cp}/volumeMounts", "value": [{"name": "scratch", "mountPath": "/scratch"}]})
        out.append(("hostpath-scratch", tmpl + [vol_op, mnt_op], "adds a hostPath volume as writable scratch space"))

    # M11 hallucinated / misspelt field alongside the fix
    if cp:
        after = _applies(res, tmpl)
        if after is not None and isinstance((get_at(after, cp) or {}).get("securityContext"), dict):
            out.append(("hallucinated-field", tmpl + [{"op": "add", "path": f"{cp}/securityContext/{rng.choice(['hardened', 'readOnlyRootFileSystem', 'nonRoot'])}", "value": True}],
                        "adds a field that does not exist in the Kubernetes API"))

    # M12 modifies an existing volume mount
    if cp and ctr.get("volumeMounts"):
        m0 = ctr["volumeMounts"][0]
        out.append(("existing-mount-change", tmpl + [{"op": "replace", "path": f"{cp}/volumeMounts/0/mountPath", "value": m0["mountPath"] + "-ro"}],
                    "moves an existing mount, breaking the application's paths"))

    # M13 resets replicas
    if get_at(res, "/spec/replicas") not in (None, 1):
        out.append(("replicas-reset", tmpl + [{"op": "replace", "path": "/spec/replicas", "value": 1}], "scales the workload down to 1"))

    # M14 privilege creep hidden behind an existing finding
    if cid == "PG002" and any(x.key == ("PG005", f.resource_index, f.subject) for x in scan_object(res, f.resource_index)):
        after = _applies(res, tmpl)
        caps = ((get_at(after, cp) or {}).get("securityContext") or {}).get("capabilities") if after else None
        if isinstance(caps, dict) and isinstance(caps.get("add"), list):
            out.append(("privilege-creep", tmpl + [{"op": "add", "path": f"{cp}/securityContext/capabilities/add/-", "value": "SYS_PTRACE"}],
                        "adds a capability while an existing PG005 finding masks it"))
        else:
            add_path = f"{cp}/securityContext/capabilities" if not isinstance(caps, dict) else f"{cp}/securityContext/capabilities/add"
            val: Any = {"add": ["SYS_PTRACE"]} if not isinstance(caps, dict) else ["SYS_PTRACE"]
            out.append(("privilege-creep", tmpl + [{"op": "add", "path": add_path, "value": val}],
                        "adds a capability while an existing PG005 finding masks it"))

    # M15 copies the redaction placeholder into an env value
    if cp and ctr.get("env"):
        out.append(("redacted-value-copied", tmpl + [{"op": "replace", "path": f"{cp}/env/0/value", "value": "<redacted>"}],
                    "overwrites an env value with the redaction placeholder"))

    # mutations must apply (except M0) to be meaningful
    return [(c, p, n) for c, p, n in out if c == "unapplicable" or _applies(res, p) is not None]


def build_corpus(seed: int, n_workloads: int) -> list[Candidate]:
    rng = random.Random(seed)
    cands: list[Candidate] = []
    for i in range(n_workloads):
        res = generate_workload(rng, i)
        for f in scan_object(res, 0):
            if not CONTROLS[f.control_id].auto_repairable:
                continue
            base = f"s{seed}-w{i}-{f.control_id}-{f.subject}"
            for name, patch in valid_variants(res, f):
                cands.append(Candidate(f"{base}-v-{name}", copy.deepcopy(res), f, patch, True, name))
            for cat, patch, note in invalid_mutants(res, f, rng):
                cands.append(Candidate(f"{base}-x-{cat}", copy.deepcopy(res), f, patch, False, cat, note))
    return cands
