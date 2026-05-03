# Deployment

Palsy can run as a local CI gate or as a self-hosted package-ingress service. Start with
CI admission, then add the API and internal mirror when a team needs central review and
promotion.

## GitHub Actions

```yaml
name: Dependency admission

on:
  pull_request:
  push:
    branches: [main]

jobs:
  dependency-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: njlane314/palsy@v0.3.0
        with:
          mode: enforce
          environment: ci
          policy: .palsy/policy.yaml
          licence: .palsy/licence.json
          report-dir: .palsy/reports
          lockfiles: |
            requirements.txt
            package-lock.json
```

Archive `.palsy/reports/` and `.palsy/permits/` as build artefacts if your governance
process needs evidence after the workflow finishes.

## GitLab CI

```yaml
stages: [test]

palsy-dependency-gate:
  image: python:3.12-slim
  stage: test
  before_script:
    - python -m pip install git+https://github.com/njlane314/palsy.git@v0.3.0
  script:
    - |
      palsy gate requirements.txt package-lock.json \
        --mode enforce \
        --environment ci \
        --policy .palsy/policy.yaml \
        --licence .palsy/licence.json \
        --report-dir .palsy/reports
  artifacts:
    when: always
    paths:
      - .palsy/reports/
      - .palsy/permits/
```

## Docker Compose API

Use Docker Compose when a team wants the API, review queue, revocations, and internal
PyPI mirror on a single host.

```bash
cp .env.example .env
# Set PALSY_API_TOKEN to a long random value.
docker compose up --build -d
curl -fsS http://127.0.0.1:8080/healthz
```

Assess a package through the self-hosted API:

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/artifacts/pypi/assess \
  -H "X-API-Token: $PALSY_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"project":"requests","version":"2.32.3","environment":"ci"}'
```

## Kubernetes

This minimal deployment uses a secret, persistent state volume, and internal service.
Harden it with your cluster ingress, network policy, backup, and secret-management
standards before production.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: palsy-api
type: Opaque
stringData:
  PALSY_API_TOKEN: replace-with-long-random-token
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: palsy-state
spec:
  accessModes: ["ReadWriteOnce"]
  resources:
    requests:
      storage: 20Gi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: palsy
spec:
  replicas: 1
  selector:
    matchLabels:
      app: palsy
  template:
    metadata:
      labels:
        app: palsy
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: palsy
          image: ghcr.io/njlane314/palsy:v0.3.0
          ports:
            - containerPort: 8080
          env:
            - name: PALSY_STATE_DIR
              value: /var/lib/palsy
            - name: PALSY_POLICY_FILE
              value: /app/config/policy.example.yaml
            - name: PALSY_REQUIRE_API_TOKEN
              value: "true"
            - name: PALSY_API_TOKEN
              valueFrom:
                secretKeyRef:
                  name: palsy-api
                  key: PALSY_API_TOKEN
          volumeMounts:
            - name: state
              mountPath: /var/lib/palsy
            - name: tmp
              mountPath: /tmp
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
      volumes:
        - name: state
          persistentVolumeClaim:
            claimName: palsy-state
        - name: tmp
          emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: palsy
spec:
  selector:
    app: palsy
  ports:
    - name: http
      port: 8080
      targetPort: 8080
```

## Internal Repository Setup

For Python teams, point installs at the approved Palsy Simple API mirror after admission:

```ini
# pip.conf
[global]
index-url = http://palsy.internal:8080/simple/
require-virtualenv = true
```

CI should assess the lockfile first and fail if no build permit is produced:

```bash
palsy gate requirements.txt --mode enforce --environment ci --permit-out .palsy/permits
palsy verify-permit .palsy/permits/requirements.txt.permit.json \
  --lockfile requirements.txt \
  --environment ci
python -m pip install -r requirements.txt
```

For npm teams, use the wrapper while the npm mirror surface is being expanded:

```bash
PALSY_URL=http://palsy.internal:8080 \
PALSY_API_TOKEN="$PALSY_API_TOKEN" \
scripts/palsy-npm-install is-number@7.0.0
```

## Operating Model

- Run `observe` first to collect dependency evidence without breaking builds.
- Move repositories to `enforce` once the policy and allowlists are stable.
- Keep `.palsy/permits/` with build artefacts for audit.
- Use revocations when a previously admitted artefact becomes unsafe.
- Keep the Palsy API token out of source control and rotate it after demos.
