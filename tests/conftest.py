from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"

DEPLOYMENT = """
apiVersion: apps/v1
kind: Deployment
metadata: {name: api, labels: {app: api}}
spec:
  replicas: 2
  selector: {matchLabels: {app: api}}
  template:
    metadata: {labels: {app: api}}
    spec:
      containers:
        - name: api
          image: ghcr.io/acme/api:1.0.0
          ports: [{name: http, containerPort: 8080}]
          env: [{name: DB_PASSWORD, value: s3cr3t-value}]
          resources: {requests: {cpu: 250m, memory: 256Mi}}
          securityContext: {runAsUser: 1000}
          volumeMounts: [{name: data, mountPath: /data}]
        - name: sidecar
          image: busybox:1.36
      volumes: [{name: data, emptyDir: {}}]
"""

CTR0 = "/spec/template/spec/containers/0"
POD = "/spec/template/spec"


@pytest.fixture
def deployment() -> dict:
    return yaml.safe_load(DEPLOYMENT)


@pytest.fixture
def deployment_text() -> str:
    return DEPLOYMENT


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch, tmp_path):
    """Never touch a real key or the user's audit DB during tests."""
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.setenv("PATCHGATE_DB", str(tmp_path / "audit.db"))
    monkeypatch.chdir(tmp_path)  # so a developer's .env file is not loaded
