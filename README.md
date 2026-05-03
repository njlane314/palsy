# Palsy

A production-shaped software supply-chain firewall for Python, npm, OCI images, and generic URL artefacts. It resolves package or image references to exact artefacts, downloads them into quarantine, verifies available digests, statically scans them, evaluates policy, promotes allowed artefacts into internal mirrors where supported, and emits signed Ed25519 permits.

The PyPI path remains fully supported, including the compatibility endpoint and Simple API mirror. Palsy now also has provider adapters for npm tarballs, OCI image metadata bundles, and generic HTTP(S) downloads with caller-supplied digests.

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
- npm install/lifecycle scripts;
- suspicious JavaScript subprocess, environment, or network references;
- OCI images that default to root, carry secret-like environment variables, or use shell/downloader entrypoints;
- mutable OCI tags when policy requires immutable digests;
- generic production artefacts without caller-supplied expected digests;
- path-traversal entries in archive members;
- fresh releases inside a configurable quarantine window;
- suspicious authority deltas from the previous approved version.

When a package is allowed, the service produces a signed permit for the exact artefact digest. Downstream CI or deployment systems can verify that permit rather than re-running the whole analysis stack.

## Architecture

```text
pip / npm / OCI / CI / API request
        |
        v
+---------------------+
| Provider resolver    |  PyPI / npm / OCI / generic URL
+----------+----------+
           |
           v
+---------------------+
| Quarantine download  |  sha256 verified
+----------+----------+
           |
           v
+---------------------+     optional      +----------------------+
| Static scanner       | ---------------> | Optional sandbox      |
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

## Assess a Package

The ecosystem-neutral endpoint is `POST /v1/artifacts/assess`:

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/artifacts/assess \
  -H 'X-API-Token: dev-token' \
  -H 'Content-Type: application/json' \
  -d '{"coordinate":{"ecosystem":"npm","name":"is-number","version":"7.0.0"},"environment":"ci"}' | jq .policy
```

Generic URL artefacts should provide an expected digest, especially for production:

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/artifacts/assess \
  -H 'X-API-Token: dev-token' \
  -H 'Content-Type: application/json' \
  -d '{"coordinate":{"ecosystem":"generic","name":"https://example.com/tool.tgz","expected_digest":"sha256:..."},"environment":"ci"}' | jq .policy
```

OCI references use `name` for the image and `version` for the tag or digest:

```json
{"coordinate":{"ecosystem":"oci","name":"docker.io/library/python","version":"sha256:...","platform":"linux/amd64"},"environment":"ci"}
```

The PyPI compatibility endpoint still accepts the original shape:

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/artifacts/pypi/assess \
  -H 'X-API-Token: dev-token' \
  -H 'Content-Type: application/json' \
  -d '{"project":"requests","version":"2.32.3","environment":"ci"}' | jq .policy
```

## Use Palsy as a CI Dependency Gate

For low-touch adoption, Palsy can run directly inside CI without first deploying the HTTP API or mirror service.

Bootstrap a repository:

```bash
palsy init
```

Run an observe-only assessment:

```bash
palsy gate requirements.txt --mode observe
```

Enforce dependency admission and write a signed build permit:

```bash
palsy gate requirements.txt \
  --mode enforce \
  --environment ci \
  --policy .palsy/policy.yaml \
  --permit-out .palsy/permits
```

Verify the permit before a build or deployment step:

```bash
palsy verify-permit .palsy/permits/requirements.txt.permit.json \
  --lockfile requirements.txt \
  --environment ci
```

The root `action.yml` also exposes Palsy as a GitHub composite action:

```yaml
name: Dependency admission

on:
  pull_request:
  push:
    branches: [main]

jobs:
  palsy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: njlane314/palsy@main
        with:
          mode: enforce
          environment: ci
          policy: .palsy/policy.yaml
          lockfiles: |
            requirements.txt
            package-lock.json
```

See [Palsy Gate](docs/PALSY_GATE.md) for the self-serve product path.

For production sandboxing, set:

```bash
export PALSY_SANDBOX_BACKEND=docker
```

Then request through the PyPI compatibility endpoint:

```json
{"project":"some-package","version":"1.2.3","environment":"prod","sandbox":true}
```

The Docker sandbox is run with `--network none`, `--cap-drop ALL`, `--security-opt no-new-privileges`, memory/CPU limits, and a Python audit-hook harness. The sandbox is not a substitute for static detection of `.pth` startup hooks, because `.pth` code runs during interpreter startup before normal userland instrumentation can be installed.

## Assess a Lockfile

The lockfile endpoint admits an exact dependency graph and issues a signed build permit only when every dependency artefact is allowed. The first supported formats are pinned Python `requirements*.txt` files and npm `package-lock.json`.

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/lockfiles/assess \
  -H 'X-API-Token: dev-token' \
  -H 'Content-Type: application/json' \
  -d '{"project":"demo-app","lockfile_name":"requirements.txt","content":"idna==3.10\npackaging==24.2\n","environment":"ci"}' | jq .
```

The response includes the lockfile digest, per-dependency decisions, any individual artefact permit IDs, and a `permit` field only when the whole graph is allowed. That build permit binds the project, environment, lockfile digest, policy hash, dependency count, and dependency artefact digests.

For CI, use the CLI wrapper. It exits `0` only for an allowed graph and exits non-zero for `review`, `deny`, HTTP errors, or unsupported lockfile shapes:

```bash
PALSY_URL=http://127.0.0.1:8080 PALSY_API_TOKEN=dev-token palsy admit-lockfile requirements.txt --project demo-app
```

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

For npm, assess and install with:

```bash
PALSY_URL=http://127.0.0.1:8080 PALSY_API_TOKEN=dev-token scripts/palsy-npm-install is-number@7.0.0
```

Approved npm tarballs are exposed through `http://127.0.0.1:8080/npm/{package}`. OCI and generic URL artefacts are assessment/permit flows; they do not yet expose a complete registry mirror.

## API summary

```text
GET  /v1/ecosystems                  List available provider adapters
POST /v1/artifacts/assess            Ecosystem-neutral assess endpoint
POST /v1/artifacts/pypi/assess       Resolve, download, scan, decide, and maybe permit
POST /v1/lockfiles/assess            Assess pinned lockfiles and maybe issue a build permit
GET  /v1/permits/{permit_id}         Fetch and verify a permit
GET  /v1/permits/by-digest/{sha256}  Fetch latest valid permit for an artefact digest
POST /v1/revocations                 Revoke digest and invalidate permits
GET  /v1/reviews                     List artefacts waiting for review
POST /v1/reviews/{sha256}/approve    Record reviewer approval and issue a permit
GET  /v1/blast-radius/{sha256}       Local artefact/permit/decision history
GET  /simple/{project}/              Approved PyPI Simple API index
GET  /npm/{package}                  Approved npm packument
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
allow_lifecycle_scripts: []
allow_embedded_interpreter: []
max_allowed_severity: medium
review_on_severity: high
permit_ttl_seconds: 604800
require_sandbox_for_prod: true
deny_oci_mutable_tags_in_prod: true
review_oci_mutable_tags_in_ci: true
require_expected_digest_for_generic_prod: true
```

The default config deliberately denies high-severity static findings. Relax this in observe mode first if you deploy it in an existing environment.

## Local static scan

```bash
palsy scan ./some-package-1.2.3-py3-none-any.whl
palsy scan ./some-npm-package-1.0.0.tgz
```

## Examples

Create and scan a local suspicious wheel:

```bash
python examples/suspicious_wheel_demo.py
```

Assess a real package through the running API:

```bash
PALSY_API_TOKEN=dev-token python examples/assess_real_package.py
PALSY_API_TOKEN=dev-token python examples/assess_universal.py
PALSY_API_TOKEN=dev-token python examples/assess_lockfile.py
```

For CI integration, see `examples/github-actions-palsy.yml`. The committed `.github/workflows/ci.yml` runs tests and builds the package on every push and pull request.

## Tests

```bash
pytest -q
```

## Operational notes

- Route CI and developer installs through this service or the wrapper; optional controls are not firewalls.
- Assess committed lockfiles in CI and require a build permit before install/build steps consume the graph.
- Use the internal PyPI/npm mirrors as the only package source in production builds where mirror support exists.
- Give dependency-resolution jobs no deployment secrets.
- For OCI and generic artefacts, enforce permit checks in CI/deployment because Palsy does not act as a full registry proxy for those ecosystems yet.
- Run the service behind TLS and keep `PALSY_API_TOKEN` enabled.
- Store `PALSY_STATE_DIR` on durable storage. It contains quarantine files, the internal mirror, SQLite state, and signing keys; losing it invalidates operational history and may rotate the permit signing key.
- For high volume, port `palsy.db.Database` to Postgres.
- Treat review decisions as failed in production unless a separate approval workflow explicitly promotes the artefact.
- Keep the signing key offline or use an HSM/KMS if permits become production deployment evidence.

## Current limitations

This is a working multi-ecosystem ingress firewall, not a complete enterprise supply-chain platform. PyPI and npm have internal mirror surfaces; OCI and generic URL support currently provide assessment, quarantine, scanning, policy decisions, and signed permits. It does not yet include package publisher identity attestations, Sigstore verification, eBPF syscall tracing, or a graph database for deployment reachability.
