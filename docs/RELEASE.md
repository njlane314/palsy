# Release Process

Palsy sells supply-chain integrity, so the project release process must produce
evidence that can be inspected by buyers.

## What a Release Produces

The release workflow in [.github/workflows/release.yml](../.github/workflows/release.yml)
runs on signed `v*` tags and produces:

- a GPG-verified GitHub tag and GitHub Release;
- Python source distribution and wheel;
- PyPI publication through Trusted Publishing;
- a GHCR Docker image;
- an SPDX JSON SBOM for the source tree;
- `SHA256SUMS` for release artefacts;
- GitHub build provenance attestations for release artefacts and the container image.

## One-Time Setup

Configure PyPI Trusted Publishing for this repository before the first release:

```text
Repository: njlane314/palsy
Workflow: release.yml
Environment: pypi
```

Configure GHCR package visibility and retention in GitHub after the first image push.

## Release Commands

Create a signed tag whose version matches `pyproject.toml`:

```bash
git status --short
git tag -s v0.3.0 -m "Palsy v0.3.0"
git push origin v0.3.0
```

The workflow deliberately fails if the tag is not signed or if the tag does not match
the Python package version.

## Local Preflight

Run these before tagging:

```bash
python -m pip install -e '.[test]' build
pytest -q
python -m build
shasum -a 256 dist/*  # macOS
docker build -t palsy:local .
```

## Verify a Release

After the workflow finishes, verify that the release contains:

- `.tar.gz` and `.whl` Python distributions;
- `palsy-source.spdx.json`;
- `SHA256SUMS`;
- build provenance attestations visible from GitHub;
- a pushed `ghcr.io/njlane314/palsy:vX.Y.Z` image;
- the same version on PyPI.

Useful checks:

```bash
gh release view v0.3.0 --repo njlane314/palsy
gh release download v0.3.0 --repo njlane314/palsy --dir /tmp/palsy-release
cd /tmp/palsy-release && shasum -a 256 -c SHA256SUMS
python -m pip install palsy==0.3.0
docker pull ghcr.io/njlane314/palsy:v0.3.0
```

## References

- PyPI Trusted Publishing: <https://docs.pypi.org/trusted-publishers/using-a-publisher/>
- GitHub artifact attestations: <https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds>
- Syft SBOM tooling: <https://oss.anchore.com/docs/guides/sbom/getting-started/>
