"""Hand-written challenge set, frozen before it was first run against the gate.

Unlike the generated corpus, these cases were written to probe the gate's *limits*: runtime-only
breakage that static checks cannot see, and legitimate fixes the conservative scope may reject.
Expected outcomes are written down per case; mismatches are reported, not tuned away.

    python -m evaluation.challenge_set
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from patchgate.checks import find_matching, scan_object
from patchgate.verifier import GATES, verify

NGINX = """
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, labels: {app: web}}
spec:
  replicas: 2
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      containers:
        - name: nginx
          image: nginx:1.27
          ports: [{name: http, containerPort: 80}, {name: metrics, containerPort: 9113}]
          resources: {requests: {cpu: 100m, memory: 128Mi}}
          securityContext: {allowPrivilegeEscalation: false, runAsNonRoot: true, runAsUser: 101,
                            capabilities: {drop: [ALL], add: [NET_BIND_SERVICE]}, seccompProfile: {type: RuntimeDefault}}
          readinessProbe: {httpGet: {path: /, port: http}}
          volumeMounts: [{name: conf, mountPath: /etc/nginx/conf.d}]
      volumes: [{name: conf, configMap: {name: web-conf}}]
"""

POSTGRES = """
apiVersion: apps/v1
kind: StatefulSet
metadata: {name: db}
spec:
  serviceName: db
  replicas: 1
  selector: {matchLabels: {app: db}}
  template:
    metadata: {labels: {app: db}}
    spec:
      containers:
        - name: postgres
          image: postgres:16.3
          ports: [{containerPort: 5432}]
          env: [{name: POSTGRES_PASSWORD, valueFrom: {secretKeyRef: {name: db, key: pw}}}]
          resources: {requests: {cpu: 500m, memory: 1Gi}, limits: {cpu: "1", memory: 2Gi}}
          readinessProbe: {exec: {command: [pg_isready]}}
          volumeMounts: [{name: data, mountPath: /var/lib/postgresql/data}]
      volumes: [{name: data, emptyDir: {}}]
"""

POSTGRES_NOPROBE = "\n".join(line for line in POSTGRES.splitlines() if "readinessProbe" not in line)

WORKER = """
apiVersion: batch/v1
kind: Job
metadata: {name: etl}
spec:
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: etl
          image: ghcr.io/acme/etl:3.1.0
          args: [--input, /data/in]
          securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: false}
"""

C = "/spec/template/spec/containers/0"
P = "/spec/template/spec"

# (id, manifest, control, subject, patch, ground-truth valid?, why)
CASES: list[tuple[str, str, str, str, list[dict[str, Any]], bool, str]] = [
    # --- runtime-only breakage: static gate is expected to ACCEPT these (known blind spot) ---
    ("rt-nginx-readonly-no-run-dir", NGINX, "PG006", "nginx",
     [{"op": "add", "path": f"{C}/securityContext/readOnlyRootFilesystem", "value": True}], False,
     "nginx writes /var/cache/nginx and /var/run/nginx.pid; without emptyDirs the pod crash-loops"),
    ("rt-postgres-nonroot", POSTGRES, "PG003", "postgres",
     [{"op": "add", "path": f"{C}/securityContext", "value": {"runAsNonRoot": True, "runAsUser": 10001}}], False,
     "official postgres image initialises its data dir as root/postgres(999); UID 10001 cannot write it"),
    ("rt-tiny-memory-limit", WORKER, "PG007", "etl",
     [{"op": "add", "path": f"{C}/resources", "value": {"limits": {"cpu": "100m", "memory": "16Mi"}}}], False,
     "16Mi is far below what the ETL process needs; OOMKilled at runtime"),
    ("rt-probe-wrong-declared-port", POSTGRES_NOPROBE, "PG011", "postgres",
     [{"op": "add", "path": f"{C}/readinessProbe", "value": {"httpGet": {"path": "/health", "port": 5432}}}], False,
     "HTTP probe against the PostgreSQL wire port always fails; pod never becomes Ready"),
    # --- clearly invalid edits the gate should REJECT ---
    ("bad-nginx-drop-bind-cap", NGINX, "PG006", "nginx",
     [{"op": "add", "path": f"{C}/securityContext/readOnlyRootFilesystem", "value": True},
      {"op": "replace", "path": f"{C}/securityContext/capabilities", "value": {"drop": ["ALL"]}}], False,
     "removes NET_BIND_SERVICE so nginx can no longer bind port 80 as UID 101"),
    ("bad-postgres-secret-to-literal", POSTGRES, "PG002", "postgres",
     [{"op": "add", "path": f"{C}/securityContext", "value": {"allowPrivilegeEscalation": False}},
      {"op": "replace", "path": f"{C}/env/0", "value": {"name": "POSTGRES_PASSWORD", "value": "changeme"}}], False,
     "inlines a literal password in place of the secret reference"),
    ("bad-etl-args-rewritten", WORKER, "PG005", "etl",
     [{"op": "add", "path": f"{C}/securityContext/capabilities", "value": {"drop": ["ALL"]}},
      {"op": "replace", "path": f"{C}/args", "value": ["--input", "/tmp/in"]}], False,
     "silently changes the program arguments"),
    ("bad-nginx-mount-readonly-volume-swap", NGINX, "PG006", "nginx",
     [{"op": "add", "path": f"{C}/securityContext/readOnlyRootFilesystem", "value": True},
      {"op": "replace", "path": f"{P}/volumes/0", "value": {"name": "conf", "emptyDir": {}}}], False,
     "replaces the configMap with an empty dir, losing the nginx configuration"),
    ("bad-db-serviceName", POSTGRES, "PG002", "postgres",
     [{"op": "add", "path": f"{C}/securityContext", "value": {"allowPrivilegeEscalation": False}},
      {"op": "replace", "path": "/spec/serviceName", "value": "db-headless"}], False,
     "changes the StatefulSet's governing service (immutable field; breaks DNS)"),
    ("bad-etl-restart-policy", WORKER, "PG010", "etl",
     [{"op": "add", "path": f"{C}/securityContext/seccompProfile", "value": {"type": "RuntimeDefault"}},
      {"op": "replace", "path": f"{P}/restartPolicy", "value": "OnFailure"}], False,
     "changes Job retry semantics"),
    ("bad-seccomp-localhost-missing-profile", WORKER, "PG010", "etl",
     [{"op": "add", "path": f"{C}/securityContext/seccompProfile", "value": {"type": "Localhost"}}], False,
     "Localhost seccomp without localhostProfile is rejected by the API server"),
    ("bad-probe-two-handlers", POSTGRES_NOPROBE, "PG011", "postgres",
     [{"op": "add", "path": f"{C}/readinessProbe", "value": {"tcpSocket": {"port": 5432}, "exec": {"command": ["pg_isready"]}}}], False,
     "a probe may only have one handler; API server rejects it"),
    ("bad-cpu-quantity", WORKER, "PG007", "etl",
     [{"op": "add", "path": f"{C}/resources", "value": {"limits": {"cpu": "half", "memory": "256Mi"}}}], False,
     "'half' is not a valid quantity"),
    # --- legitimate fixes: the gate SHOULD accept; some may be falsely rejected (conservative scope) ---
    ("ok-runasgroup-companion", WORKER, "PG003", "etl",
     [{"op": "add", "path": f"{C}/securityContext/runAsNonRoot", "value": True},
      {"op": "add", "path": f"{C}/securityContext/runAsUser", "value": 10001},
      {"op": "add", "path": f"{C}/securityContext/runAsGroup", "value": 10001}], True,
     "adding runAsGroup alongside runAsUser is common, harmless practice"),
    ("ok-nginx-readonly-with-emptydirs", NGINX, "PG006", "nginx",
     [{"op": "add", "path": f"{C}/securityContext/readOnlyRootFilesystem", "value": True},
      {"op": "add", "path": f"{P}/volumes/-", "value": {"name": "cache", "emptyDir": {}}},
      {"op": "add", "path": f"{P}/volumes/-", "value": {"name": "run", "emptyDir": {}}},
      {"op": "add", "path": f"{C}/volumeMounts/-", "value": {"name": "cache", "mountPath": "/var/cache/nginx"}},
      {"op": "add", "path": f"{C}/volumeMounts/-", "value": {"name": "run", "mountPath": "/var/run"}}], True,
     "the correct nginx fix: read-only root plus writable cache/run dirs"),
    ("ok-emptydir-with-sizelimit", WORKER, "PG006", "etl",
     [{"op": "replace", "path": f"{C}/securityContext/readOnlyRootFilesystem", "value": True},
      {"op": "add", "path": f"{P}/volumes", "value": [{"name": "tmp", "emptyDir": {"sizeLimit": "1Gi"}}]},
      {"op": "add", "path": f"{C}/volumeMounts", "value": [{"name": "tmp", "mountPath": "/tmp"}]}], True,
     "bounded emptyDir scratch space"),
    ("ok-limits-with-requests", WORKER, "PG007", "etl",
     [{"op": "add", "path": f"{C}/resources", "value": {"requests": {"cpu": "250m", "memory": "512Mi"},
                                                        "limits": {"cpu": "1", "memory": "1Gi"}}}], True,
     "adds both requests and limits to a container with none"),
    ("ok-seccomp-localhost", WORKER, "PG010", "etl",
     [{"op": "add", "path": f"{C}/securityContext/seccompProfile", "value": {"type": "Localhost", "localhostProfile": "profiles/etl.json"}}], True,
     "Localhost profile with a path is valid (assuming the profile exists on nodes)"),
    ("ok-probe-with-timings", POSTGRES_NOPROBE, "PG011", "postgres",
     [{"op": "add", "path": f"{C}/readinessProbe", "value": {"exec": {"command": ["pg_isready", "-U", "postgres"]},
                                                             "initialDelaySeconds": 10, "periodSeconds": 5, "failureThreshold": 6}}], True,
     "exec probe with tuned timings"),
    ("ok-configmap-mount-made-readonly", NGINX, "PG006", "nginx",
     [{"op": "add", "path": f"{C}/securityContext/readOnlyRootFilesystem", "value": True},
      {"op": "add", "path": f"{C}/volumeMounts/0/readOnly", "value": True},
      {"op": "add", "path": f"{P}/volumes/-", "value": {"name": "cache", "emptyDir": {}}},
      {"op": "add", "path": f"{P}/volumes/-", "value": {"name": "run", "emptyDir": {}}},
      {"op": "add", "path": f"{C}/volumeMounts/-", "value": {"name": "cache", "mountPath": "/var/cache/nginx"}},
      {"op": "add", "path": f"{C}/volumeMounts/-", "value": {"name": "run", "mountPath": "/var/run"}}], True,
     "marking a configMap mount read-only is harmless (configMap volumes are read-only anyway)"),
    ("ok-liveness-added-too", POSTGRES_NOPROBE, "PG011", "postgres",
     [{"op": "add", "path": f"{C}/readinessProbe", "value": {"tcpSocket": {"port": 5432}}},
      {"op": "add", "path": f"{C}/livenessProbe", "value": {"tcpSocket": {"port": 5432}, "initialDelaySeconds": 30}}], True,
     "adds a liveness probe as well; arguably useful, but outside the PG011 contract"),
]


def run() -> dict[str, Any]:
    gates = ["relint-full", "patchgate"]
    results = []
    for cid, text, control, subject, patch, valid, why in CASES:
        obj = yaml.safe_load(text)
        f = find_matching(scan_object(obj, 0), (control, 0, subject))
        if f is None:
            results.append({"id": cid, "error": f"finding {control}/{subject} not present"})
            continue
        row: dict[str, Any] = {"id": cid, "control": control, "valid": valid, "why": why}
        for g in gates:
            v, _ = verify(obj, f, patch, GATES[g])
            row[g] = v.accepted
            if g == "patchgate":
                row["reasons"] = v.reasons
        row["patchgate_correct"] = row["patchgate"] == valid
        row["relint_correct"] = row["relint-full"] == valid
        results.append(row)
    ok = [r for r in results if "error" not in r]
    inv = [r for r in ok if not r["valid"]]
    val = [r for r in ok if r["valid"]]
    summary = {g: {"false_accepts": sum(r[g] for r in inv), "invalid": len(inv),
                   "false_rejects": sum(not r[g] for r in val), "valid": len(val)} for g in gates}
    return {"summary": summary, "cases": results}


def main() -> int:
    out = run()
    Path("evaluation/results").mkdir(parents=True, exist_ok=True)
    Path("evaluation/results/challenge_set.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    for r in out["cases"]:
        if "error" in r:
            print(f"ERROR {r['id']}: {r['error']}")
            continue
        print(f"{r['id']:40} truth={'valid' if r['valid'] else 'invalid':8} relint={'A' if r['relint-full'] else 'R'} "
              f"patchgate={'A' if r['patchgate'] else 'R'} {'' if r['patchgate_correct'] else '<-- patchgate wrong'}")
    print(json.dumps(out["summary"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
