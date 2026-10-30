import pytest

from patchgate.manifest import ManifestError, get_at, load_manifest, pod_spec_prefix
from patchgate.patch import PatchError, apply_patch, changed_paths, parse_patch


def test_load_multi_document_and_list_expansion():
    text = "kind: Service\nmetadata: {name: s}\n---\nkind: List\nitems:\n  - {kind: Pod, metadata: {name: p}, spec: {containers: [{name: c, image: x:1}]}}\n"
    m = load_manifest(text)
    assert [r.ref for r in m.resources] == ["Service/s", "Pod/p"]
    assert [r.ref for r in m.workloads()] == ["Pod/p"]


def test_yaml_aliases_rejected():
    with pytest.raises(ManifestError, match="aliases"):
        load_manifest("a: &x [1, 2]\nb: *x\n")


def test_invalid_and_oversized_input():
    with pytest.raises(ManifestError):
        load_manifest("key: [unclosed")
    with pytest.raises(ManifestError, match="not a mapping"):
        load_manifest("- 1\n- 2\n")
    with pytest.raises(ManifestError, match="larger"):
        load_manifest("a: " + "x" * 1_000_001)
    with pytest.raises(ManifestError, match="no Kubernetes"):
        load_manifest("---\n")


def test_pod_spec_prefix_per_kind():
    assert pod_spec_prefix({"kind": "CronJob"}) == "/spec/jobTemplate/spec/template/spec"
    assert pod_spec_prefix({"kind": "Pod"}) == "/spec"
    assert pod_spec_prefix({"kind": "Service"}) is None


def test_apply_add_replace_remove_and_append(deployment):
    ops = parse_patch([
        {"op": "add", "path": "/spec/template/spec/containers/0/securityContext/allowPrivilegeEscalation", "value": False},
        {"op": "replace", "path": "/spec/replicas", "value": 3},
        {"op": "add", "path": "/spec/template/spec/volumes/-", "value": {"name": "tmp", "emptyDir": {}}},
        {"op": "remove", "path": "/spec/template/spec/containers/1"},
    ])
    out = apply_patch(deployment, ops)
    assert out["spec"]["replicas"] == 3
    assert out["spec"]["template"]["spec"]["volumes"][-1]["name"] == "tmp"
    assert len(out["spec"]["template"]["spec"]["containers"]) == 1
    assert deployment["spec"]["replicas"] == 2  # original untouched


def test_pointer_escaping():
    doc = {"metadata": {"annotations": {"a/b": "1", "c~d": "2"}}}
    out = apply_patch(doc, parse_patch([{"op": "replace", "path": "/metadata/annotations/a~1b", "value": "x"},
                                        {"op": "remove", "path": "/metadata/annotations/c~0d"}]))
    assert out["metadata"]["annotations"] == {"a/b": "x"}
    assert get_at(out, "/metadata/annotations/a~1b") == "x"


@pytest.mark.parametrize("raw,msg", [
    ({"op": "add"}, "array"),
    ([], "empty"),
    ([{"op": "move", "from": "/a", "path": "/b"}], "invalid"),
    ([{"op": "add", "path": "/a"}], "value"),
    ([{"op": "add", "path": "a", "value": 1}], "invalid"),
    ([{"op": "add", "path": "/a", "value": 1}] * 41, "more than"),
])
def test_parse_patch_rejects_bad_input(raw, msg):
    with pytest.raises(PatchError, match=msg):
        parse_patch(raw)


@pytest.mark.parametrize("op", [
    {"op": "replace", "path": "/spec/missing", "value": 1},
    {"op": "remove", "path": "/spec/missing"},
    {"op": "add", "path": "/spec/a/b", "value": 1},
    {"op": "replace", "path": "/spec/template/spec/containers/9", "value": {}},
    {"op": "test", "path": "/spec/replicas", "value": 7},
])
def test_apply_failures_are_atomic(deployment, op):
    with pytest.raises(PatchError):
        apply_patch(deployment, parse_patch([{"op": "replace", "path": "/spec/replicas", "value": 9}, op]))
    assert deployment["spec"]["replicas"] == 2


def test_changed_paths_leaf_level():
    before = {"a": {"b": 1, "c": [1, 2]}, "d": True}
    after = {"a": {"b": 1, "c": [1, 3, 4], "e": {"f": "x"}}, "d": "true"}
    assert sorted(changed_paths(before, after)) == ["/a/c/1", "/a/c/2", "/a/e/f", "/d"]
    assert changed_paths(before, before) == []
