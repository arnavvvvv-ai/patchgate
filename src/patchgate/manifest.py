"""Loading Kubernetes manifests safely and locating the pod template inside each workload."""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any

import yaml

MAX_MANIFEST_BYTES = 1_000_000
MAX_DOCUMENTS = 200

# Where the PodSpec lives for each supported workload kind (JSON-pointer prefix).
POD_SPEC_PREFIX: dict[str, str] = {
    "Pod": "/spec",
    "Deployment": "/spec/template/spec",
    "StatefulSet": "/spec/template/spec",
    "DaemonSet": "/spec/template/spec",
    "ReplicaSet": "/spec/template/spec",
    "Job": "/spec/template/spec",
    "CronJob": "/spec/jobTemplate/spec/template/spec",
}


class ManifestError(ValueError):
    """The input could not be parsed as a safe, bounded set of Kubernetes objects."""


class _NoAliasSafeLoader(yaml.SafeLoader):
    """SafeLoader that refuses YAML aliases (prevents 'billion laughs' expansion)."""

    def compose_node(self, parent, index):  # type: ignore[override]
        if self.check_event(yaml.AliasEvent):
            event = self.peek_event()
            raise ManifestError(f"YAML aliases are not allowed (line {event.start_mark.line + 1})")
        return super().compose_node(parent, index)


@dataclass
class Resource:
    index: int
    obj: dict[str, Any]

    @property
    def kind(self) -> str:
        return str(self.obj.get("kind", ""))

    @property
    def name(self) -> str:
        return str((self.obj.get("metadata") or {}).get("name", f"doc-{self.index}"))

    @property
    def ref(self) -> str:
        return f"{self.kind}/{self.name}"

    @property
    def is_workload(self) -> bool:
        return self.kind in POD_SPEC_PREFIX and pod_spec(self.obj) is not None


@dataclass
class Manifest:
    resources: list[Resource] = field(default_factory=list)

    def workloads(self) -> list[Resource]:
        return [r for r in self.resources if r.is_workload]

    def to_yaml(self) -> str:
        return dump_documents([r.obj for r in self.resources])

    def clone(self) -> "Manifest":
        return Manifest([Resource(r.index, copy.deepcopy(r.obj)) for r in self.resources])


def load_manifest(text: str) -> Manifest:
    if len(text.encode("utf-8")) > MAX_MANIFEST_BYTES:
        raise ManifestError(f"manifest larger than {MAX_MANIFEST_BYTES} bytes")
    try:
        docs = list(yaml.load_all(text, Loader=_NoAliasSafeLoader))
    except ManifestError:
        raise
    except yaml.YAMLError as exc:
        raise ManifestError(f"invalid YAML: {exc}") from exc
    docs = [d for d in docs if d is not None]
    if len(docs) > MAX_DOCUMENTS:
        raise ManifestError(f"more than {MAX_DOCUMENTS} YAML documents")
    resources: list[Resource] = []
    for i, doc in enumerate(docs):
        if not isinstance(doc, dict):
            raise ManifestError(f"document {i} is not a mapping")
        # Expand List objects (kubectl get -o yaml output) into individual resources.
        if doc.get("kind") == "List" and isinstance(doc.get("items"), list):
            for item in doc["items"]:
                if isinstance(item, dict):
                    resources.append(Resource(len(resources), item))
            continue
        resources.append(Resource(len(resources), doc))
    if not resources:
        raise ManifestError("no Kubernetes objects found")
    return Manifest(resources)


def dump_documents(docs: list[dict[str, Any]]) -> str:
    return "---\n".join(yaml.safe_dump(d, sort_keys=False, default_flow_style=False) for d in docs)


# ---------------------------------------------------------------- JSON pointer helpers

def escape_token(token: str | int) -> str:
    return str(token).replace("~", "~0").replace("/", "~1")


def unescape_token(token: str) -> str:
    return token.replace("~1", "/").replace("~0", "~")


def split_pointer(pointer: str) -> list[str]:
    if pointer == "":
        return []
    if not pointer.startswith("/"):
        raise ValueError(f"JSON pointer must start with '/': {pointer!r}")
    return [unescape_token(t) for t in pointer[1:].split("/")]


def join_pointer(tokens: list[str | int]) -> str:
    return "".join("/" + escape_token(t) for t in tokens)


def get_at(doc: Any, pointer: str, default: Any = None) -> Any:
    cur = doc
    for tok in split_pointer(pointer):
        if isinstance(cur, dict):
            if tok not in cur:
                return default
            cur = cur[tok]
        elif isinstance(cur, list):
            if not tok.isdigit() or int(tok) >= len(cur):
                return default
            cur = cur[int(tok)]
        else:
            return default
    return cur


def pod_spec_prefix(obj: dict[str, Any]) -> str | None:
    return POD_SPEC_PREFIX.get(str(obj.get("kind", "")))


def pod_spec(obj: dict[str, Any]) -> dict[str, Any] | None:
    prefix = pod_spec_prefix(obj)
    if prefix is None:
        return None
    spec = get_at(obj, prefix)
    return spec if isinstance(spec, dict) else None


@dataclass(frozen=True)
class ContainerRef:
    """A container located by list ('containers' / 'initContainers') and index."""

    group: str
    index: int
    name: str

    def pointer(self, pod_prefix: str) -> str:
        return f"{pod_prefix}/{self.group}/{self.index}"


def iter_containers(spec: dict[str, Any]) -> list[tuple[ContainerRef, dict[str, Any]]]:
    out: list[tuple[ContainerRef, dict[str, Any]]] = []
    for group in ("initContainers", "containers"):
        items = spec.get(group) or []
        if not isinstance(items, list):
            continue
        for i, c in enumerate(items):
            if isinstance(c, dict):
                out.append((ContainerRef(group, i, str(c.get("name", f"{group}[{i}]"))), c))
    return out
