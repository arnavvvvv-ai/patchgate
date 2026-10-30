"""The acceptance gate: decides whether a candidate patch is a *verified* repair of one finding.

A candidate is accepted only if every enabled check passes:

  G1 apply        the restricted JSON Patch applies cleanly to the target resource
  G2 structural   the patch introduces no new schema/type errors (unknown keys, wrong types, bad quantities)
  G3 target       the targeted finding is gone after the patch
  G4 no-new       no finding that was absent before appears after the patch
  G5 scope        every changed leaf path lies inside the control's repair contract
  G6 invariants   behaviour-defining fields are preserved and semantic constraints hold

Re-running the linter (G3 + G4) is what existing remediation pipelines rely on. G2, G5 and G6 are the
additional checks this project contributes; they are individually switchable for ablation studies.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any

from pydantic import BaseModel

from .checks import ALLOWED_ADD_CAPS, CONTROLS, Finding, pattern_matches, scan_object
from .manifest import get_at, iter_containers, pod_spec, pod_spec_prefix, split_pointer
from .patch import PatchError, PatchOp, apply_patch, changed_paths, parse_patch


@dataclass(frozen=True)
class GateConfig:
    name: str = "patchgate"
    target: bool = True
    no_new: bool = True
    structural: bool = True
    scope: bool = True
    invariants: bool = True


GATES: dict[str, GateConfig] = {
    "apply-only": GateConfig("apply-only", target=False, no_new=False, structural=False, scope=False, invariants=False),
    "relint-target": GateConfig("relint-target", no_new=False, structural=False, scope=False, invariants=False),
    "relint-full": GateConfig("relint-full", structural=False, scope=False, invariants=False),
    "patchgate": GateConfig("patchgate"),
    "patchgate-no-structural": GateConfig("patchgate-no-structural", structural=False),
    "patchgate-no-scope": GateConfig("patchgate-no-scope", scope=False),
    "patchgate-no-invariants": GateConfig("patchgate-no-invariants", invariants=False),
}


class CheckResult(BaseModel):
    name: str
    passed: bool
    details: list[str] = []


class Verdict(BaseModel):
    accepted: bool
    gate: str
    checks: list[CheckResult]
    changed_paths: list[str] = []
    resolved: list[str] = []
    introduced: list[str] = []
    elapsed_ms: float = 0.0

    @property
    def reasons(self) -> list[str]:
        return [f"[{c.name}] {d}" for c in self.checks if not c.passed for d in (c.details or ["failed"])]


# ---------------------------------------------------------------- quantities

_MEM = {"Ki": 2**10, "Mi": 2**20, "Gi": 2**30, "Ti": 2**40, "Pi": 2**50, "Ei": 2**60,
        "k": 10**3, "M": 10**6, "G": 10**9, "T": 10**12, "P": 10**15, "E": 10**18, "m": Decimal("0.001")}
_QTY = re.compile(r"^([+]?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)(Ki|Mi|Gi|Ti|Pi|Ei|k|M|G|T|P|E|m)?$")


def parse_quantity(value: Any) -> Decimal | None:
    """Parse a Kubernetes resource.Quantity (e.g. '500m', '1.5', '256Mi'). Returns None if invalid."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return Decimal(str(value)) if value >= 0 else None
    if not isinstance(value, str):
        return None
    m = _QTY.match(value.strip())
    if not m:
        return None
    try:
        num = Decimal(m.group(1))
    except InvalidOperation:
        return None
    return num * Decimal(_MEM[m.group(2)]) if m.group(2) else num


# ---------------------------------------------------------------- structural validation

CONTAINER_KEYS = {"name", "image", "command", "args", "workingDir", "ports", "envFrom", "env", "resources",
                  "resizePolicy", "restartPolicy", "volumeMounts", "volumeDevices", "livenessProbe", "readinessProbe",
                  "startupProbe", "lifecycle", "terminationMessagePath", "terminationMessagePolicy",
                  "imagePullPolicy", "securityContext", "stdin", "stdinOnce", "tty"}
CONTAINER_SC_KEYS = {"capabilities", "privileged", "seLinuxOptions", "windowsOptions", "runAsUser", "runAsGroup",
                     "runAsNonRoot", "readOnlyRootFilesystem", "allowPrivilegeEscalation", "procMount",
                     "seccompProfile", "appArmorProfile"}
POD_SC_KEYS = {"seLinuxOptions", "windowsOptions", "runAsUser", "runAsGroup", "runAsNonRoot", "supplementalGroups",
               "supplementalGroupsPolicy", "fsGroup", "sysctls", "fsGroupChangePolicy", "seccompProfile",
               "appArmorProfile", "seLinuxChangePolicy"}
SC_BOOLS = {"privileged", "runAsNonRoot", "readOnlyRootFilesystem", "allowPrivilegeEscalation"}
SC_INTS = {"runAsUser", "runAsGroup", "fsGroup"}
PROBE_HANDLERS = {"httpGet", "tcpSocket", "exec", "grpc"}
PROBE_KEYS = PROBE_HANDLERS | {"initialDelaySeconds", "timeoutSeconds", "periodSeconds", "successThreshold",
                               "failureThreshold", "terminationGracePeriodSeconds"}
VOLUME_SOURCES = {"hostPath", "emptyDir", "secret", "configMap", "persistentVolumeClaim", "projected", "downwardAPI",
                  "nfs", "csi", "ephemeral", "image", "iscsi", "fc", "cephfs", "rbd", "azureFile", "azureDisk",
                  "gcePersistentDisk", "awsElasticBlockStore", "glusterfs", "portworxVolume", "flexVolume", "cinder",
                  "flocker", "vsphereVolume", "quobyte", "photonPersistentDisk", "scaleIO", "storageos", "gitRepo"}


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _validate_sc(sc: Any, allowed: set[str], where: str, errs: list[str]) -> None:
    if not isinstance(sc, dict):
        errs.append(f"{where}/securityContext is not an object")
        return
    for k, v in sc.items():
        if k not in allowed:
            errs.append(f"{where}/securityContext has unknown field {k!r}")
        elif k in SC_BOOLS and not isinstance(v, bool):
            errs.append(f"{where}/securityContext/{k} must be a boolean, got {type(v).__name__}")
        elif k in SC_INTS and (not _is_int(v) or v < 0):
            errs.append(f"{where}/securityContext/{k} must be a non-negative integer")
        elif k == "capabilities":
            if not isinstance(v, dict) or set(v) - {"add", "drop"}:
                errs.append(f"{where}/securityContext/capabilities must contain only 'add'/'drop'")
            else:
                for part in ("add", "drop"):
                    if part in v and (not isinstance(v[part], list) or not all(isinstance(x, str) for x in v[part])):
                        errs.append(f"{where}/securityContext/capabilities/{part} must be a list of strings")
        elif k == "seccompProfile":
            if not isinstance(v, dict) or v.get("type") not in ("RuntimeDefault", "Localhost", "Unconfined"):
                errs.append(f"{where}/securityContext/seccompProfile.type must be RuntimeDefault, Localhost or Unconfined")
            elif v.get("type") == "Localhost" and not isinstance(v.get("localhostProfile"), str):
                errs.append(f"{where}/securityContext/seccompProfile Localhost requires localhostProfile")


def _validate_probe(p: Any, where: str, errs: list[str]) -> None:
    if not isinstance(p, dict):
        errs.append(f"{where} must be an object")
        return
    unknown = set(p) - PROBE_KEYS
    if unknown:
        errs.append(f"{where} has unknown fields {sorted(unknown)}")
    handlers = [h for h in PROBE_HANDLERS if h in p]
    if len(handlers) != 1:
        errs.append(f"{where} must define exactly one handler (httpGet/tcpSocket/exec/grpc), found {len(handlers)}")
    for k in PROBE_KEYS - PROBE_HANDLERS:
        if k in p and (not _is_int(p[k]) or p[k] < 0):
            errs.append(f"{where}/{k} must be a non-negative integer")
    for h in ("httpGet", "tcpSocket"):
        if h in p and (not isinstance(p[h], dict) or "port" not in p[h]):
            errs.append(f"{where}/{h} requires a port")


def structural_errors(obj: dict[str, Any]) -> list[str]:
    """A focused subset of Kubernetes API validation for the pod template of a workload."""
    errs: list[str] = []
    spec = pod_spec(obj)
    prefix = pod_spec_prefix(obj) or ""
    if spec is None:
        return [f"{obj.get('kind')} has no pod spec at {prefix}"]
    if not isinstance(spec.get("containers"), list) or not spec["containers"]:
        errs.append(f"{prefix}/containers must be a non-empty list")
    vols = spec.get("volumes", [])
    vol_names: set[str] = set()
    if not isinstance(vols, list):
        errs.append(f"{prefix}/volumes must be a list")
        vols = []
    for i, v in enumerate(vols):
        if not isinstance(v, dict) or not isinstance(v.get("name"), str):
            errs.append(f"{prefix}/volumes/{i} needs a string name")
            continue
        if v["name"] in vol_names:
            errs.append(f"duplicate volume name {v['name']!r}")
        vol_names.add(v["name"])
        sources = [k for k in v if k in VOLUME_SOURCES]
        if len(sources) != 1:
            errs.append(f"volume {v['name']!r} must have exactly one source, found {len(sources)}")
        unknown = set(v) - VOLUME_SOURCES - {"name"}
        if unknown:
            errs.append(f"volume {v['name']!r} has unknown fields {sorted(unknown)}")
    for k in ("hostNetwork", "hostPID", "hostIPC", "automountServiceAccountToken"):
        if k in spec and not isinstance(spec[k], bool):
            errs.append(f"{prefix}/{k} must be a boolean")
    if "securityContext" in spec:
        _validate_sc(spec["securityContext"], POD_SC_KEYS, prefix, errs)
    names: set[str] = set()
    for ref, c in iter_containers(spec):
        where = ref.pointer(prefix)
        if not isinstance(c.get("name"), str) or not isinstance(c.get("image"), str) or not c.get("image"):
            errs.append(f"{where} needs string name and image")
        if ref.name in names:
            errs.append(f"duplicate container name {ref.name!r}")
        names.add(ref.name)
        unknown = set(c) - CONTAINER_KEYS
        if unknown:
            errs.append(f"{where} has unknown fields {sorted(unknown)}")
        if "securityContext" in c:
            _validate_sc(c["securityContext"], CONTAINER_SC_KEYS, where, errs)
        res = c.get("resources")
        if res is not None:
            if not isinstance(res, dict) or set(res) - {"limits", "requests", "claims"}:
                errs.append(f"{where}/resources may contain only limits/requests/claims")
            else:
                for part in ("limits", "requests"):
                    for rk, rv in (res.get(part) or {}).items():
                        if parse_quantity(rv) is None:
                            errs.append(f"{where}/resources/{part}/{rk} is not a valid quantity: {rv!r}")
        for probe in ("livenessProbe", "readinessProbe", "startupProbe"):
            if probe in c:
                _validate_probe(c[probe], f"{where}/{probe}", errs)
        mounts = c.get("volumeMounts", [])
        if not isinstance(mounts, list):
            errs.append(f"{where}/volumeMounts must be a list")
            mounts = []
        paths: set[str] = set()
        for j, m in enumerate(mounts):
            if not isinstance(m, dict) or not isinstance(m.get("name"), str) or not isinstance(m.get("mountPath"), str):
                errs.append(f"{where}/volumeMounts/{j} needs string name and mountPath")
                continue
            if m["name"] not in vol_names:
                errs.append(f"{where}/volumeMounts/{j} references undefined volume {m['name']!r}")
            if m["mountPath"] in paths:
                errs.append(f"{where} mounts {m['mountPath']!r} twice")
            paths.add(m["mountPath"])
            if "readOnly" in m and not isinstance(m["readOnly"], bool):
                errs.append(f"{where}/volumeMounts/{j}/readOnly must be a boolean")
    return errs


# ---------------------------------------------------------------- behavioural invariants

PROTECTED_CONTAINER_FIELDS = ("image", "command", "args", "workingDir", "ports", "env", "envFrom", "lifecycle",
                              "livenessProbe", "startupProbe", "imagePullPolicy", "stdin", "stdinOnce", "tty",
                              "volumeDevices", "restartPolicy")
POD_FIELDS_OPEN_TO_REPAIR = {"containers", "initContainers", "volumes", "securityContext",
                             "hostNetwork", "hostPID", "hostIPC"}
# A new writable mount may only cover conventional scratch locations; anywhere else it could hide files the
# image ships (an emptyDir over /usr/share/nginx/html empties the site). Anything else is left to a human.
SCRATCH_MOUNT_PREFIXES = ("/tmp", "/var/tmp", "/run", "/var/run", "/var/cache", "/var/log")
# Settings that decide which identity and syscall filter a container starts with; pod-level values are inherited.
START_IDENTITY_KEYS = ("runAsNonRoot", "runAsUser", "runAsGroup", "seccompProfile")


def _without(d: dict[str, Any], keys: set[str]) -> dict[str, Any]:
    return {k: v for k, v in d.items() if k not in keys}


def _outside_pod_spec(obj: dict[str, Any]) -> Any:
    """The object with the pod spec removed: identity, labels, selectors, replicas, schedules, strategy..."""
    tokens = split_pointer(pod_spec_prefix(obj) or "")
    def strip(node: Any, depth: int) -> Any:
        if depth == len(tokens) - 1:
            return _without(node, {tokens[-1]}) if isinstance(node, dict) else node
        if not isinstance(node, dict):
            return node
        return {k: (strip(v, depth + 1) if k == tokens[depth] else v) for k, v in node.items()}
    return strip(obj, 0) if tokens else obj


def _is_scratch(path: Any) -> bool:
    p = str(path).rstrip("/")
    return any(p == x or p.startswith(x + "/") for x in SCRATCH_MOUNT_PREFIXES)


def _covers(parent: str, child: str) -> bool:
    parent, child = parent.rstrip("/"), child.rstrip("/")
    return child == parent or child.startswith(parent + "/")


def _effective_sc(container: dict[str, Any], spec: dict[str, Any], key: str) -> Any:
    csc = container.get("securityContext") if isinstance(container.get("securityContext"), dict) else {}
    if key in csc:
        return csc[key]
    psc = spec.get("securityContext") if isinstance(spec.get("securityContext"), dict) else {}
    return psc.get(key)


def _side_effect_violations(before: dict[str, Any], after: dict[str, Any], finding: Finding | None,
                            prior_findings: list[Finding] | None = None) -> list[str]:
    """Effects of pod-level edits on containers other than the finding's subject."""
    out: list[str] = []
    bs, as_ = pod_spec(before) or {}, pod_spec(after) or {}
    if finding is not None and prior_findings is None:
        prior_findings = scan_object(before)
    prior = {(f.control_id, f.subject) for f in prior_findings or []}
    for group in ("initContainers", "containers"):
        bc = [c for c in (bs.get(group) or []) if isinstance(c, dict)]
        ac = [c for c in (as_.get(group) or []) if isinstance(c, dict)]
        if [c.get("name") for c in bc] != [c.get("name") for c in ac]:
            continue  # reported by the container-set invariant
        for b, a in zip(bc, ac):
            name = a.get("name")
            refused_after = _effective_sc(a, as_, "runAsNonRoot") is True and _effective_sc(a, as_, "runAsUser") == 0
            refused_before = _effective_sc(b, bs, "runAsNonRoot") is True and _effective_sc(b, bs, "runAsUser") == 0
            if refused_after and not refused_before:
                out.append(f"container {name!r}: now must run as non-root but is set to UID 0, so it would be refused at start")
            if finding is None or name == finding.subject:
                continue
            changed = [k for k in START_IDENTITY_KEYS if _effective_sc(b, bs, k) != _effective_sc(a, as_, k)]
            if changed and (finding.control_id, name) not in prior:
                out.append(f"pod-level change alters container {name!r} ({', '.join(changed)}), "
                           f"which had no {finding.control_id} finding")
    return out


def invariant_violations(before: dict[str, Any], after: dict[str, Any], finding: Finding | None = None,
                         prior_findings: list[Finding] | None = None) -> list[str]:
    out: list[str] = []
    if _outside_pod_spec(before) != _outside_pod_spec(after):
        diff = [p for p in changed_paths(_outside_pod_spec(before), _outside_pod_spec(after))]
        out.append(f"workload identity/controller fields changed (e.g. selector, labels, replicas): {diff[:5]}")
    bs, as_ = pod_spec(before) or {}, pod_spec(after) or {}
    if _without(bs, POD_FIELDS_OPEN_TO_REPAIR) != _without(as_, POD_FIELDS_OPEN_TO_REPAIR):
        keys = sorted(k for k in set(bs) | set(as_) if k not in POD_FIELDS_OPEN_TO_REPAIR and bs.get(k) != as_.get(k))
        out.append(f"pod-level scheduling/identity fields changed: {keys}")
    bvols, avols = bs.get("volumes") or [], as_.get("volumes") or []
    if not isinstance(avols, list) or avols[: len(bvols)] != bvols:
        out.append("pre-existing volumes were modified, removed or reordered")
    else:
        for v in avols[len(bvols):]:
            if not (isinstance(v, dict) and set(v) == {"name", "emptyDir"}):
                out.append(f"new volume {v.get('name') if isinstance(v, dict) else v!r} is not a plain emptyDir")
    for group in ("initContainers", "containers"):
        bc = [c for c in (bs.get(group) or []) if isinstance(c, dict)]
        ac = [c for c in (as_.get(group) or []) if isinstance(c, dict)]
        if [c.get("name") for c in bc] != [c.get("name") for c in ac]:
            out.append(f"{group} set changed: {[c.get('name') for c in bc]} -> {[c.get('name') for c in ac]}")
            continue
        aports_by_c = {}
        for b, a in zip(bc, ac):
            name = b.get("name")
            for f in PROTECTED_CONTAINER_FIELDS:
                if b.get(f) != a.get(f):
                    out.append(f"container {name!r}: protected field {f!r} changed")
            if "readinessProbe" in b and b["readinessProbe"] != a.get("readinessProbe"):
                out.append(f"container {name!r}: existing readinessProbe changed")
            bm, am = b.get("volumeMounts") or [], a.get("volumeMounts") or []
            if not isinstance(am, list) or am[: len(bm)] != bm:
                out.append(f"container {name!r}: pre-existing volumeMounts modified or removed")
            else:
                existing = [m.get("mountPath") for m in bm if isinstance(m, dict) and isinstance(m.get("mountPath"), str)]
                for m in am[len(bm):]:
                    path = m.get("mountPath") if isinstance(m, dict) else None
                    if not isinstance(path, str):
                        continue  # reported by the structural check
                    if not _is_scratch(path):
                        out.append(f"container {name!r}: new mount at {path!r} could hide files shipped in the image; "
                                   f"only scratch locations {', '.join(SCRATCH_MOUNT_PREFIXES)} may be added")
                    for e in existing:
                        if _covers(path, e):
                            out.append(f"container {name!r}: new mount at {path!r} hides the existing mount {e!r}")
            bres = b.get("resources") if isinstance(b.get("resources"), dict) else {}
            ares = a.get("resources") if isinstance(a.get("resources"), dict) else {}
            for part in ("requests", "limits"):
                bpart = bres.get(part) or {}
                apart = ares.get(part) or {}
                for rk, rv in bpart.items():
                    if apart.get(rk) != rv:
                        out.append(f"container {name!r}: existing {part}.{rk} changed")
            for rk in ("cpu", "memory"):
                lim = parse_quantity((ares.get("limits") or {}).get(rk)) if rk in (ares.get("limits") or {}) else None
                req = parse_quantity((ares.get("requests") or {}).get(rk)) if rk in (ares.get("requests") or {}) else None
                if lim is not None and req is not None and lim < req:
                    out.append(f"container {name!r}: limits.{rk} is below requests.{rk}")
            bcaps = set((((b.get("securityContext") or {}).get("capabilities") or {}).get("add") or []))
            acaps = set((((a.get("securityContext") or {}).get("capabilities") or {}).get("add") or []))
            if acaps - bcaps:
                out.append(f"container {name!r}: new capabilities added {sorted(acaps - bcaps)}")
            dropped_allowed = (bcaps & ALLOWED_ADD_CAPS) - acaps
            if dropped_allowed:
                out.append(f"container {name!r}: removes capabilities it is allowed to keep {sorted(dropped_allowed)}")
            ports = a.get("ports") or []
            aports_by_c[name] = ({p.get("containerPort") for p in ports if isinstance(p, dict)},
                                 {p.get("name") for p in ports if isinstance(p, dict) and p.get("name")})
            if a.get("readinessProbe") != b.get("readinessProbe") and isinstance(a.get("readinessProbe"), dict):
                numbers, names = aports_by_c[name]
                for h in ("httpGet", "tcpSocket", "grpc"):
                    handler = a["readinessProbe"].get(h)
                    if isinstance(handler, dict) and "port" in handler:
                        port = handler["port"]
                        if not ((_is_int(port) and port in numbers) or (isinstance(port, str) and port in names)):
                            out.append(f"container {name!r}: readinessProbe targets undeclared port {port!r}")
            bsc, asc = b.get("securityContext") or {}, a.get("securityContext") or {}
            if isinstance(asc, dict) and asc.get("runAsUser") == 0 and (not isinstance(bsc, dict) or bsc.get("runAsUser") != 0):
                out.append(f"container {name!r}: runAsUser set to 0 (root)")
    bpsc, apsc = bs.get("securityContext") or {}, as_.get("securityContext") or {}
    if isinstance(apsc, dict) and apsc.get("runAsUser") == 0 and (not isinstance(bpsc, dict) or bpsc.get("runAsUser") != 0):
        out.append("pod securityContext.runAsUser set to 0 (root)")
    out.extend(_side_effect_violations(before, after, finding, prior_findings))
    return out


# ---------------------------------------------------------------- the gate

def verify(resource: dict[str, Any], finding: Finding, patch: Any, gate: GateConfig = GATES["patchgate"]) -> tuple[Verdict, dict[str, Any] | None]:
    """Run the gate. Returns the verdict and (if the patch applied) the patched resource."""
    t0 = time.perf_counter()
    checks: list[CheckResult] = []

    def done(after: dict[str, Any] | None, **kw: Any) -> tuple[Verdict, dict[str, Any] | None]:
        accepted = all(c.passed for c in checks)
        v = Verdict(accepted=accepted, gate=gate.name, checks=checks, elapsed_ms=(time.perf_counter() - t0) * 1000, **kw)
        return v, after

    try:
        ops: list[PatchOp] = parse_patch(patch)
        after = apply_patch(resource, ops)
        if not isinstance(after, dict):
            raise PatchError("patch replaced the resource with a non-object")
        checks.append(CheckResult(name="apply", passed=True))
    except (PatchError, ValueError) as exc:
        checks.append(CheckResult(name="apply", passed=False, details=[str(exc)]))
        return done(None)

    paths = changed_paths(resource, after)
    if not paths:
        checks.append(CheckResult(name="effect", passed=False, details=["patch changes nothing"]))
        return done(after)

    before_findings = scan_object(resource, finding.resource_index)
    after_findings = scan_object(after, finding.resource_index) if pod_spec(after) is not None else []
    before_keys = {f.key for f in before_findings}
    after_keys = {f.key for f in after_findings}
    resolved = sorted(":".join(map(str, k)) for k in before_keys - after_keys)
    introduced = sorted(":".join(map(str, k)) for k in after_keys - before_keys)

    if gate.structural:
        new_errs = sorted(set(structural_errors(after)) - set(structural_errors(resource)))
        checks.append(CheckResult(name="structural", passed=not new_errs, details=new_errs))
    if gate.target:
        still = finding.key in after_keys
        checks.append(CheckResult(name="target", passed=not still and pod_spec(after) is not None,
                                  details=[f"{finding.control_id} on {finding.subject!r} is still present"] if still else
                                  ([] if pod_spec(after) is not None else ["pod spec missing after patch"])))
    if gate.no_new:
        checks.append(CheckResult(name="no-new-findings", passed=not introduced,
                                  details=[f"patch introduces finding {k}" for k in introduced]))
    if gate.scope:
        allowed = CONTROLS[finding.control_id].allowed_patterns(finding)
        outside = [p for p in paths if not any(pattern_matches(a, p) for a in allowed)]
        checks.append(CheckResult(name="scope", passed=not outside,
                                  details=[f"change outside the {finding.control_id} repair contract: {p}" for p in outside[:8]]))
    if gate.invariants:
        viol = invariant_violations(resource, after, finding, before_findings)
        checks.append(CheckResult(name="invariants", passed=not viol, details=viol))
    return done(after, changed_paths=paths, resolved=resolved, introduced=introduced)


__all__ = ["GATES", "GateConfig", "Verdict", "CheckResult", "verify", "structural_errors", "invariant_violations",
           "parse_quantity", "get_at"]
