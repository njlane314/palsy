# Public Release Checklist

Use this before making the Palsy repository public or listing the action.

## Repository Hygiene

- Confirm no real secrets, API tokens, private customer policy, or production state are
  committed.
- Confirm `state/`, `.env`, `.venv/`, `logs/`, `dist/`, and generated report artefacts stay
  ignored or disposable.
- Confirm the explicit root [LICENSE](../LICENSE) file matches the `Apache-2.0` project
  metadata.
- Confirm `pyproject.toml`, `palsy/__init__.py`, and the FastAPI app expose the same version.
- Rotate any token or signing key that has ever appeared in local demos or screenshots.
- Review commit history for private file paths or customer names.
- Run the full test suite and package build.

## Action Release

- Keep [action.yml](../action.yml) at the repository root.
- Create a signed release tag:

```bash
git tag -s v0.3.0 -m "Palsy v0.3.0"
git push origin v0.3.0
```

- Let [.github/workflows/release.yml](../.github/workflows/release.yml) publish the GitHub
  Release, PyPI package, GHCR Docker image, SBOM, checksums, and build provenance
  attestations.
- Tell users to pin the action to the tag:

```yaml
- uses: njlane314/palsy@v0.3.0
  with:
    mode: enforce
    environment: ci
    policy: .palsy/policy.yaml
    lockfiles: |
      requirements.txt
      package-lock.json
```

## Landing Page

- Enable GitHub Pages from `/docs` on `main`.
- Replace Stripe placeholder URLs in [docs/index.html](index.html).
- Check the landing page on desktop and mobile before sharing it.
- Keep the first viewport focused on the product promise:

```text
Block unapproved PyPI/npm packages before they enter CI.
```

## Trial and Fulfilment

- Generate each trial with:

```bash
palsy licence trial --email buyer@example.com --out .palsy/licence.json
```

- Send trial users the licence file and the private policy/update bundle.
- Track the trial expiry date outside the public repository.
- Convert active pilots to Stripe subscriptions before sending renewed private bundles.

## Make the Repository Public

Changing visibility exposes code and commit history. Do this only after the checks above:

```bash
gh repo edit njlane314/palsy --visibility public
```

## Marketplace Later

- Create the GitHub App or Marketplace listing only after Stripe subscriptions and support
  fulfilment are working.
- Apply for publisher verification before using paid Marketplace plans.
- Add webhook handling for purchases, trial starts, plan changes, and cancellations.
- Keep pricing consistent with outside Stripe offers.
