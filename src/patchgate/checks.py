"""Deterministic misconfiguration controls and their *repair contracts*.

Each control declares, besides its detection logic, the exact set of JSON-pointer patterns a repair
for that control is allowed to touch (its scope). The verifier uses that scope to reject patches that
"fix" a finding by editing unrelated parts of the workload. The controls follow the Kubernetes Pod
Security Standards (baseline/restricted profiles) plus two common reliability checks.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .manifest import Manifest, Resource, get_at, iter_containers, pod_spec, pod_spec_prefix, split_pointer

ALLOWED_ADD_CAPS = {"NET_BIND_SERVICE"}
PROBE_KINDS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet"}


@dataclass(frozen=True)
class Finding:
    control_id: str
    resource_index: int
    resource_ref: str
    subject: str                 # container name, volume name, or "pod"
    pointer: str                 # JSON pointer of the offending object
    pod_prefix: str
    container_pointer: str | None
    message: str

    @property
    def key(self) -> tuple[str, int, str]:
        return (self.control_id, self.resource_index, self.subject)

    @property
    def control(self) -> "Control":
        return CONTROLS[self.control_id]

    def to_dict(self) -> dict[str, Any]:
        c = self.control
        return {
            "control_id": self.control_id,
            "title": c.title,
            "severity": c.severity,
            "resource_index": self.resource_index,
            "resource": self.resource_ref,
            "subject": self.subject,
            "pointer": self.pointer,
            "message": self.message,
            "auto_repairable": c.auto_repairable,
        }


@dataclass(frozen=True)
class Control:
    id: str
    title: str
    severity: str
    category: str
    rationale: str
    scope: tuple[str, ...]
    auto_repairable: bool = True
    runtime_assumptions: tuple[str, ...] = ()
    check: Callable[[Resource], list[Finding]] | None = None

    def allowed_patterns(self, finding: Finding) -> list[str]:
        out = []
        for pattern in self.scope:
            if "{ctr}" in pattern and finding.container_pointer is None:
                continue
            out.append(pattern.replace("{pod}", finding.pod_prefix).replace("{ctr}", finding.container_pointer or ""))
        return out


def pattern_matches(pattern: str, pointer: str) -> bool:
    """Match a JSON pointer against a pattern where '*' is one segment and a trailing '**' is any suffix."""
    p = split_pointer(pattern)
    t = split_pointer(pointer)
    for i, seg in enumerate(p):
        if seg == "**":
            return i == len(p) - 1 and len(t) >= i
        if i >= len(t):
            return False
        if seg != "*" and seg != t[i]:
            return False
    return len(p) == len(t)


# ---------------------------------------------------------------- helpers

def _sc(obj: dict[str, Any] | None) -> dict[str, Any]:
    sc = (obj or {}).get("securityContext")
    return sc if isinstance(sc, dict) else {}


def _effective(container: dict[str, Any], spec: dict[str, Any], key: str) -> Any:
    csc = _sc(container)
    if key in csc:
        return csc[key]
    return _sc(spec).get(key)


def _per_container(control_id: str, groups: tuple[str, ...], predicate: Callable[[dict, dict], str | None]):
    def check(res: Resource) -> list[Finding]:
        spec = pod_spec(res.obj)
        prefix = pod_spec_prefix(res.obj)
        if spec is None or prefix is None:
            return []
        out = []
        for ref, c in iter_containers(spec):
            if ref.group not in groups:
                continue
            msg = predicate(c, spec)
            if msg:
                cp = ref.pointer(prefix)
                out.append(Finding(control_id, res.index, res.ref, ref.name, cp, prefix, cp, msg))
        return out
    return check


def _image_tag(image: str) -> str | None:
    if "@" in image:
        return "@digest"
    last = image.rsplit("/", 1)[-1]
    return last.split(":", 1)[1] if ":" in last else None


# ---------------------------------------------------------------- predicates

def _privileged(c, spec):
    return "container runs privileged" if _sc(c).get("privileged") is True else None


def _priv_esc(c, spec):
    return None if _sc(c).get("allowPrivilegeEscalation") is False else "allowPrivilegeEscalation is not set to false"


def _non_root(c, spec):
    if _effective(c, spec, "runAsUser") == 0:
        return "container is configured to run as UID 0 (root)"
    if _effective(c, spec, "runAsNonRoot") is not True:
        return "runAsNonRoot is not set to true at pod or container level"
    return None


def _caps(c, spec):
    caps = _sc(c).get("capabilities")
    caps = caps if isinstance(caps, dict) else {}
    drop = caps.get("drop") if isinstance(caps.get("drop"), list) else []
    add = caps.get("add") if isinstance(caps.get("add"), list) else []
    bad_add = [a for a in add if str(a) not in ALLOWED_ADD_CAPS]
    if bad_add:
        return f"adds disallowed capabilities {bad_add}"
    if "ALL" not in [str(d) for d in drop]:
        return "capabilities.drop does not contain ALL"
    return None


def _ro_rootfs(c, spec):
    return None if _sc(c).get("readOnlyRootFilesystem") is True else "readOnlyRootFilesystem is not true"


def _limits(c, spec):
    limits = (c.get("resources") or {}).get("limits") if isinstance(c.get("resources"), dict) else None
    limits = limits if isinstance(limits, dict) else {}
    missing = [k for k in ("cpu", "memory") if k not in limits]
    return f"missing resource limits: {', '.join(missing)}" if missing else None


def _image(c, spec):
    image = str(c.get("image", ""))
    tag = _image_tag(image)
    if tag is None:
        return f"image {image!r} has no tag (implicit :latest)"
    if tag == "latest":
        return f"image {image!r} uses the mutable :latest tag"
    return None


def _seccomp(c, spec):
    prof = _effective(c, spec, "seccompProfile")
    t = prof.get("type") if isinstance(prof, dict) else None
    return None if t in ("RuntimeDefault", "Localhost") else "seccompProfile.type is not RuntimeDefault or Localhost"


def _host_namespaces(res: Resource) -> list[Finding]:
    spec = pod_spec(res.obj)
    prefix = pod_spec_prefix(res.obj)
    if spec is None or prefix is None:
        return []
    on = [k for k in ("hostNetwork", "hostPID", "hostIPC") if spec.get(k) is True]
    if not on:
        return []
    return [Finding("PG004", res.index, res.ref, "pod", prefix, prefix, None, f"pod shares host namespaces: {', '.join(on)}")]


def _host_path(res: Resource) -> list[Finding]:
    spec = pod_spec(res.obj)
    prefix = pod_spec_prefix(res.obj)
    if spec is None or prefix is None:
        return []
    out = []
    for i, v in enumerate(spec.get("volumes") or []):
        if isinstance(v, dict) and "hostPath" in v:
            out.append(Finding("PG008", res.index, res.ref, f"volume:{v.get('name', i)}", f"{prefix}/volumes/{i}",
                               prefix, None, f"volume {v.get('name')!r} mounts a hostPath ({(v.get('hostPath') or {}).get('path')})"))
    return out


def _readiness(res: Resource) -> list[Finding]:
    if res.kind not in PROBE_KINDS:
        return []
    def pred(c, spec):
        if c.get("ports") and not c.get("readinessProbe"):
            return "container exposes ports but has no readinessProbe"
        return None
    return _per_container("PG011", ("containers",), pred)(res)


# ---------------------------------------------------------------- registry

_SC = "{ctr}/securityContext"
CONTROLS: dict[str, Control] = {c.id: c for c in [
    Control("PG001", "Privileged container", "high", "security",
            "Privileged containers have full access to the host; PSS baseline forbids them.",
            (f"{_SC}/privileged",), check=_per_container("PG001", ("initContainers", "containers"), _privileged)),
    Control("PG002", "Privilege escalation allowed", "medium", "security",
            "allowPrivilegeEscalation must be false under PSS restricted.",
            (f"{_SC}/allowPrivilegeEscalation",), check=_per_container("PG002", ("initContainers", "containers"), _priv_esc)),
    Control("PG003", "Container may run as root", "medium", "security",
            "PSS restricted requires runAsNonRoot=true and forbids runAsUser=0.",
            (f"{_SC}/runAsNonRoot", f"{_SC}/runAsUser", "{pod}/securityContext/runAsNonRoot", "{pod}/securityContext/runAsUser"),
            runtime_assumptions=("The image must be able to start as a non-root UID.",),
            check=_per_container("PG003", ("initContainers", "containers"), _non_root)),
    Control("PG004", "Host namespaces shared", "high", "security",
            "hostNetwork/hostPID/hostIPC break isolation; PSS baseline forbids them.",
            ("{pod}/hostNetwork", "{pod}/hostPID", "{pod}/hostIPC"),
            runtime_assumptions=("The workload must not depend on host networking or host process visibility.",),
            check=_host_namespaces),
    Control("PG005", "Excess Linux capabilities", "medium", "security",
            "PSS restricted requires dropping ALL capabilities and only allows adding NET_BIND_SERVICE.",
            (f"{_SC}/capabilities/**",),
            runtime_assumptions=("The process must not need the dropped capabilities.",),
            check=_per_container("PG005", ("initContainers", "containers"), _caps)),
    Control("PG006", "Writable root filesystem", "low", "security",
            "A read-only root filesystem prevents tampering with binaries; writable paths need explicit volumes.",
            (f"{_SC}/readOnlyRootFilesystem", "{ctr}/volumeMounts/*/**", "{ctr}/volumeMounts", "{pod}/volumes/*/**", "{pod}/volumes"),
            runtime_assumptions=("Every path the process writes to must be covered by a writable volume mount.",),
            check=_per_container("PG006", ("initContainers", "containers"), _ro_rootfs)),
    Control("PG007", "Missing resource limits", "low", "reliability",
            "Containers without CPU/memory limits can starve neighbours on the node.",
            ("{ctr}/resources/limits/cpu", "{ctr}/resources/limits/memory", "{ctr}/resources/requests/cpu", "{ctr}/resources/requests/memory"),
            runtime_assumptions=("Limits must be large enough for the workload's real peak usage.",),
            check=_per_container("PG007", ("containers",), _limits)),
    Control("PG008", "hostPath volume", "high", "security",
            "hostPath exposes the node filesystem; replacing it changes data semantics, so it needs a human decision.",
            (), auto_repairable=False, check=_host_path),
    Control("PG009", "Mutable image tag", "low", "reliability",
            "Untagged or :latest images make deployments non-reproducible; choosing a version is a behaviour change.",
            (), auto_repairable=False, check=_per_container("PG009", ("initContainers", "containers"), _image)),
    Control("PG010", "No seccomp profile", "low", "security",
            "PSS restricted requires seccompProfile RuntimeDefault or Localhost.",
            (f"{_SC}/seccompProfile/**", f"{_SC}/seccompProfile", "{pod}/securityContext/seccompProfile/**", "{pod}/securityContext/seccompProfile"),
            check=_per_container("PG010", ("initContainers", "containers"), _seccomp)),
    Control("PG011", "Missing readiness probe", "low", "reliability",
            "Without a readiness probe, traffic is routed to pods before they can serve it.",
            ("{ctr}/readinessProbe/**", "{ctr}/readinessProbe"),
            runtime_assumptions=("The probe endpoint must actually reflect application readiness.",),
            check=_readiness),
]}


def scan_resource(res: Resource) -> list[Finding]:
    if not res.is_workload:
        return []
    out: list[Finding] = []
    for control in CONTROLS.values():
        if control.check is not None:
            out.extend(control.check(res))
    return out


def scan(manifest: Manifest) -> list[Finding]:
    out: list[Finding] = []
    for res in manifest.resources:
        out.extend(scan_resource(res))
    return out


def scan_object(obj: dict[str, Any], index: int = 0) -> list[Finding]:
    return scan_resource(Resource(index, obj))


def find_matching(findings: list[Finding], key: tuple[str, int, str]) -> Finding | None:
    return next((f for f in findings if f.key == key), None)


__all__ = ["CONTROLS", "Control", "Finding", "get_at", "pattern_matches", "scan", "scan_object", "scan_resource"]
