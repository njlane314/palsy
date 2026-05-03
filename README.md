# Palsy

A production-shaped PyPI ingress firewall for Python dependencies. It resolves PyPI releases to exact artefacts, downloads them into quarantine, verifies SHA-256, statically scans wheels/source distributions, optionally imports them inside a Docker sandbox, evaluates policy, promotes allowed artefacts into an internal Simple API mirror, and emits signed Ed25519 permits.

This implementation is intentionally focused on Python/PyPI because that is where the recent `.pth`/import-time backdoor class matters. The same architecture can be extended to npm, Maven, OCI, Go modules, and NuGet.

## What it enforces

The firewall blocks or requires review for signals such as:

- executable `.pth` files, which run during Python startup;
- `sitecustomize.py` or `usercustomize.py` startup hooks;
- sensitive behaviour in package `__init__.py`;
- top-level subprocess, socket, HTTP, or credential access behaviour;
- hidden `_runtime` or runtime-staging directories;
- embedded interpreters such as Bun, Node, or Deno;
- native binaries in packages not allowlisted for native code;
- large obfuscated blobs or base64-like payloads;
- malformed or invalid wheel `RECORD` hashes;
- path-traversal entries in archive members;
- fresh releases inside a configurable quarantine window;
- suspicious authority deltas from the previous approved version.

When a package is allowed, the service produces a signed permit for the exact artefact digest. Downstream CI or deployment systems can verify that permit rather than re-running the whole analysis stack.

## Architecture

```text
pip / CI / API request
        |
        v
+---------------------+
| PyPI resolver        |  GET /pypi/{project}/{version}/json
+----------+----------+
           |
           v
+---------------------+
| Quarantine download  |  sha256 verified
+----------+----------+
           |
           v
+---------------------+     optional      +----------------------+
| Static scanner       | ---------------> | Docker import sandbox |
+----------+----------+                  +----------------------+
           |
           v
+---------------------+
| Policy engine        |
+----------+----------+
           |
    allow / review / deny
           |
           v
+---------------------+       +----------------------+
| Internal mirror      | <---> | Signed permit ledger |
+---------------------+       +----------------------+
```

## Run locally

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
PALSY_API_TOKEN=dev-token PALSY_STATE_DIR=./state PALSY_POLICY_FILE=./config/policy.example.yaml palsy serve --host 127.0.0.1 --port 8080
```

or:

```bash
cp .env.example .env
# Edit .env and set PALSY_API_TOKEN to a long random value.
docker compose up --build
```

The API is available at `http://127.0.0.1:8080/docs`.

## Assess a package

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/artifacts/pypi/assess \
  -H 'X-API-Token: dev-token' \
  -H 'Content-Type: application/json' \
  -d '{"project":"requests","version":"2.32.3","environment":"ci"}' | jq .policy
```

For production sandboxing, set:

```bash
export PALSY_SANDBOX_BACKEND=docker
```

Then request:

```json
{"project":"some-package","version":"1.2.3","environment":"prod","sandbox":true}
```

The Docker sandbox is run with `--network none`, `--cap-drop ALL`, `--security-opt no-new-privileges`, memory/CPU limits, and a Python audit-hook harness. The sandbox is not a substitute for static detection of `.pth` startup hooks, because `.pth` code runs during interpreter startup before normal userland instrumentation can be installed.

## Install through the approved mirror

First assess/admit the exact version. If allowed, install using the internal Simple API mirror:

```bash
pip install --index-url http://127.0.0.1:8080/simple/ requests==2.32.3
```

or use the wrapper:

```bash
PALSY_URL=http://127.0.0.1:8080 PALSY_API_TOKEN=dev-token scripts/palsy-pip-install requests==2.32.3
```

The wrapper calls the assessment API first, then invokes pip against the internal mirror only if the policy decision is `allow`.
Set `PALSY_API_TOKEN` for the wrapper when API authentication is enabled, which is the default.

## API summary

```text
POST /v1/artifacts/pypi/assess       Resolve, download, scan, decide, and maybe permit
GET  /v1/permits/{permit_id}         Fetch and verify a permit
GET  /v1/permits/by-digest/{sha256}  Fetch latest valid permit for an artefact digest
POST /v1/revocations                 Revoke digest and invalidate permits
GET  /v1/reviews                     List artefacts waiting for review
POST /v1/reviews/{sha256}/approve    Record reviewer approval and issue a permit
GET  /v1/blast-radius/{sha256}       Local artefact/permit/decision history
GET  /simple/{project}/              Approved PyPI Simple API index
GET  /files/{sha256}/{filename}      Approved artefact content
GET  /v1/public-key                  Ed25519 public key for permit verification
```

Protected endpoints require `PALSY_API_TOKEN` by default. Send it as either `X-API-Token` or a bearer token. For local-only experiments, set `PALSY_REQUIRE_API_TOKEN=false`; do not use that setting for shared environments.

## Review flow

When policy returns `review`, Palsy stores the artefact in quarantine and keeps its status as `review`.

```bash
curl -sS http://127.0.0.1:8080/v1/reviews \
  -H 'X-API-Token: dev-token' | jq .
```

After a human review, approve the exact digest:

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/reviews/{sha256}/approve \
  -H 'X-API-Token: dev-token' \
  -H 'Content-Type: application/json' \
  -d '{"environment":"ci","reviewer":"security","reason":"Reviewed findings and accepted this version."}' | jq .
```

The approval records reviewer, reason, timestamp, and policy hash, promotes the artefact into the mirror, and issues a signed permit.

## Policy

Policy is configured by YAML. Example:

```yaml
name: pypi-default
mode: enforce
minimum_release_age_seconds:
  default: 86400
  dev: 0
  ci: 3600
  prod: 86400
allow_pth_exec:
  - setuptools
  - pip
allow_native_code:
  - numpy
  - scipy
  - cryptography
max_allowed_severity: medium
review_on_severity: high
permit_ttl_seconds: 604800
require_sandbox_for_prod: true
```

The default config deliberately denies high-severity static findings. Relax this in observe mode first if you deploy it in an existing environment.

## Local static scan

```bash
palsy scan ./some-package-1.2.3-py3-none-any.whl
```

## Examples

Create and scan a local suspicious wheel:

```bash
python examples/suspicious_wheel_demo.py
```

Assess a real package through the running API:

```bash
PALSY_API_TOKEN=dev-token python examples/assess_real_package.py
```

For CI integration, see `examples/github-actions-palsy.yml`. The committed `.github/workflows/ci.yml` runs tests and builds the package on every push and pull request.

## Tests

```bash
pytest -q
```

## Operational notes

- Route CI and developer installs through this service or the wrapper; optional controls are not firewalls.
- Use the internal mirror as the only package source in production builds.
- Give dependency-resolution jobs no deployment secrets.
- Run the service behind TLS and keep `PALSY_API_TOKEN` enabled.
- Store `PALSY_STATE_DIR` on durable storage. It contains quarantine files, the internal mirror, SQLite state, and signing keys; losing it invalidates operational history and may rotate the permit signing key.
- For high volume, port `palsy.db.Database` to Postgres.
- Treat review decisions as failed in production unless a separate approval workflow explicitly promotes the artefact.
- Keep the signing key offline or use an HSM/KMS if permits become production deployment evidence.

## Current limitations

This is a complete working implementation for PyPI artefact ingress, not a universal supply-chain platform. It does not yet include OCI image admission, package publisher identity attestations, Sigstore verification, eBPF syscall tracing, or a graph database for lockfile/build/image/deployment reachability. The code is structured so those controls can be added behind the same `Permit` and `PolicyContext` abstractions.
