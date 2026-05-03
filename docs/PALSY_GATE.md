# Palsy Gate

Palsy Gate is the self-serve CI entry point for Palsy.

It is designed for teams that do not want a hosted service or deployment engagement. The gate runs inside the customer's CI environment, assesses pinned dependency lockfiles, applies policy, and emits signed build permits for admitted dependency graphs.

The product promise is deliberately narrow:

```text
No permit, no build.
```

## What this adds

- `palsy init` bootstraps `.palsy/policy.yaml` and CI examples.
- `palsy gate` performs local lockfile admission without requiring the HTTP API.
- `palsy verify-permit` verifies a signed build permit against a lockfile.
- `action.yml` lets users run Palsy directly as a GitHub composite action.
- `palsy licence trial` creates a 14-day trial licence for private policy/update bundles.
- `palsy gate --licence` validates that licence before admitting the lockfile.

The HTTP API and internal mirror remain available for teams that want a fuller self-hosted server later. The first adoption path is now a single CI job.

## Quick start

Install the CLI:

```bash
python -m pip install git+https://github.com/njlane314/palsy.git
```

Initialise a repository:

```bash
palsy init
```

Run in observe mode first:

```bash
palsy gate requirements.txt --mode observe
```

Switch to enforcement:

```bash
palsy gate requirements.txt --mode enforce --permit-out .palsy/permits
```

Verify the signed build permit before a production build step:

```bash
palsy verify-permit .palsy/permits/requirements.txt.permit.json \
  --lockfile requirements.txt \
  --environment ci
```

## GitHub Actions

After `palsy init`, the generated workflow looks like this:

```yaml
name: Palsy dependency gate

on:
  pull_request:
  push:
    branches: [main]

jobs:
  dependency-gate:
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

For production use, pin the action to a release tag rather than `main`.

## CLI behaviour

`palsy gate` supports two execution modes:

```text
observe   print the admission result but exit 0 unless the assessment itself fails
enforce   exit 1 when any lockfile decision is review or deny
```

By default, the command looks for these lockfiles in the current directory:

```text
requirements*.txt
package-lock.json
```

You can pass explicit files instead:

```bash
palsy gate requirements.txt services/api/requirements-prod.txt package-lock.json
```

The default state directory is `.palsy/state`. It stores quarantine files, scanner state, database state, and the signing key used for build permits.

## Permit verification

A build permit is signed over:

- project name;
- lockfile name;
- lockfile digest;
- dependency count;
- admitted dependency artefact digests;
- policy name and hash;
- environment;
- expiry timestamp.

`palsy verify-permit` checks the Ed25519 signature, expiry, decision, environment, project, and lockfile digest.

Example:

```bash
palsy verify-permit .palsy/permits/requirements.txt.permit.json \
  --lockfile requirements.txt \
  --project my-service \
  --environment ci
```

## Open-core packaging

The open-source CLI should stay useful enough to reveal risk and prove the admission workflow. The commercial version should package convenience, governance, and automation rather than a personal service.

Suggested packaging:

```text
Community
  local scans
  local lockfile admission
  JSON/SARIF reports
  community docs

IngressShield Team
  CI enforcement bundle
  signed build-permit workflow
  policy templates
  multi-repo GitHub/GitLab examples
  commercial Docker images
  update stream

IngressShield Business
  self-hosted API server
  PyPI/npm mirror surfaces
  review queue
  revocations
  Postgres
  audit exports
  Slack/Jira/GitHub issue automation
```

Suggested paid SKUs:

```text
IngressShield Team
  GBP 199/month or GBP 1,999/year
  CI enforcement, signed build permits, policy templates, audit bundles

IngressShield Business
  GBP 999/month or GBP 9,999/year
  self-hosted API, mirrors, review queue, Postgres, multi-project state
```

The important boundary is operational: no hosted service is required, and the customer does not need a deployment engagement to get the first value.

## Commercial Launch Assets

- Landing page: [docs/index.html](index.html)
- Monetisation plan: [docs/MONETISATION.md](MONETISATION.md)
- Public release checklist: [docs/PUBLIC_RELEASE_CHECKLIST.md](PUBLIC_RELEASE_CHECKLIST.md)

Generate a buyer trial licence:

```bash
palsy licence trial --email buyer@example.com --out .palsy/licence.json
palsy licence check --licence .palsy/licence.json
palsy gate requirements.txt --mode enforce --licence .palsy/licence.json
```
