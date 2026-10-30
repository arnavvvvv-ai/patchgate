"""A deliberately restricted RFC 6902 JSON Patch engine plus a leaf-level structural diff.

Only ``add``, ``remove``, ``replace`` and ``test`` are supported. ``move`` and ``copy`` are refused
because they make the scope of an edit harder to audit and are never needed for a repair.
"""
from __future__ import annotations

import copy
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from .manifest import join_pointer, split_pointer

MAX_OPS = 40
_MISSING = object()


class PatchError(ValueError):
    """The patch is malformed or cannot be applied to the target document."""


class PatchOp(BaseModel):
    op: Literal["add", "remove", "replace", "test"]
    path: str = Field(min_length=2, max_length=512)
    value: Any = None

    @field_validator("path")
    @classmethod
    def _pointer(cls, v: str) -> str:
        if not v.startswith("/"):
            raise ValueError("path must be a JSON pointer starting with '/'")
        return v

    def to_json(self) -> dict[str, Any]:
        d: dict[str, Any] = {"op": self.op, "path": self.path}
        if self.op in ("add", "replace", "test"):
            d["value"] = self.value
        return d


def parse_patch(raw: Any) -> list[PatchOp]:
    if not isinstance(raw, list):
        raise PatchError("patch must be a JSON array of operations")
    if not raw:
        raise PatchError("patch is empty")
    if len(raw) > MAX_OPS:
        raise PatchError(f"patch has more than {MAX_OPS} operations")
    ops: list[PatchOp] = []
    for i, item in enumerate(raw):
        if isinstance(item, PatchOp):
            ops.append(item)
            continue
        if not isinstance(item, dict):
            raise PatchError(f"operation {i} is not an object")
        if item.get("op") in ("add", "replace", "test") and "value" not in item:
            raise PatchError(f"operation {i} ({item.get('op')}) has no 'value'")
        try:
            ops.append(PatchOp.model_validate(item))
        except Exception as exc:  # pydantic.ValidationError
            raise PatchError(f"operation {i} invalid: {exc.errors()[0]['msg'] if hasattr(exc, 'errors') else exc}") from exc
    return ops


def _parent(doc: Any, tokens: list[str]) -> Any:
    cur = doc
    for tok in tokens[:-1]:
        if isinstance(cur, dict):
            if tok not in cur:
                raise PatchError(f"path segment {tok!r} does not exist")
            cur = cur[tok]
        elif isinstance(cur, list):
            if not tok.isdigit() or int(tok) >= len(cur):
                raise PatchError(f"list index {tok!r} out of range")
            cur = cur[int(tok)]
        else:
            raise PatchError(f"cannot descend into scalar at {tok!r}")
    return cur


def apply_patch(doc: dict[str, Any], ops: list[PatchOp]) -> dict[str, Any]:
    """Apply ``ops`` to a deep copy of ``doc``. All-or-nothing: raises PatchError on any failure."""
    out = copy.deepcopy(doc)
    for n, op in enumerate(ops):
        tokens = split_pointer(op.path)
        parent = _parent(out, tokens)
        last = tokens[-1]
        value = copy.deepcopy(op.value)
        try:
            if isinstance(parent, dict):
                exists = last in parent
                if op.op == "add":
                    parent[last] = value
                elif op.op == "replace":
                    if not exists:
                        raise PatchError(f"replace target {op.path} does not exist")
                    parent[last] = value
                elif op.op == "remove":
                    if not exists:
                        raise PatchError(f"remove target {op.path} does not exist")
                    del parent[last]
                elif op.op == "test":
                    if not exists or parent[last] != value:
                        raise PatchError(f"test failed at {op.path}")
            elif isinstance(parent, list):
                if last == "-" and op.op == "add":
                    parent.append(value)
                    continue
                if not last.isdigit():
                    raise PatchError(f"invalid list index {last!r}")
                idx = int(last)
                if op.op == "add":
                    if idx > len(parent):
                        raise PatchError(f"add index {idx} out of range")
                    parent.insert(idx, value)
                else:
                    if idx >= len(parent):
                        raise PatchError(f"index {idx} out of range at {op.path}")
                    if op.op == "replace":
                        parent[idx] = value
                    elif op.op == "remove":
                        del parent[idx]
                    elif op.op == "test" and parent[idx] != value:
                        raise PatchError(f"test failed at {op.path}")
            else:
                raise PatchError(f"parent of {op.path} is a scalar")
        except PatchError as exc:
            raise PatchError(f"op {n}: {exc}") from None
    return out


# ---------------------------------------------------------------- leaf diff

def _leaves(value: Any, tokens: list[str | int]) -> list[str]:
    if isinstance(value, dict) and value:
        out: list[str] = []
        for k, v in value.items():
            out.extend(_leaves(v, tokens + [k]))
        return out
    if isinstance(value, list) and value:
        out = []
        for i, v in enumerate(value):
            out.extend(_leaves(v, tokens + [i]))
        return out
    return [join_pointer(tokens)]


def changed_paths(before: Any, after: Any, _tokens: list[str | int] | None = None) -> list[str]:
    """Leaf-level JSON pointers whose value differs (added, removed or modified) between two trees."""
    tokens = _tokens or []
    if type(before) is not type(after):
        return sorted(set(_leaves(before, tokens)) | set(_leaves(after, tokens)))
    if isinstance(before, dict):
        out: list[str] = []
        for k in list(before.keys()) + [k for k in after.keys() if k not in before]:
            b = before.get(k, _MISSING)
            a = after.get(k, _MISSING)
            if b is _MISSING:
                out.extend(_leaves(a, tokens + [k]))
            elif a is _MISSING:
                out.extend(_leaves(b, tokens + [k]))
            else:
                out.extend(changed_paths(b, a, tokens + [k]))
        return out
    if isinstance(before, list):
        out = []
        for i in range(max(len(before), len(after))):
            if i >= len(before):
                out.extend(_leaves(after[i], tokens + [i]))
            elif i >= len(after):
                out.extend(_leaves(before[i], tokens + [i]))
            else:
                out.extend(changed_paths(before[i], after[i], tokens + [i]))
        return out
    return [] if before == after else [join_pointer(tokens)]
