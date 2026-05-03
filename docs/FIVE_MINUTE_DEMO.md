# Five-Minute Demo

This demo shows the core product story: a malicious PyPI wheel is quarantined, scanned,
reviewed, and denied before it can enter a build.

Run it locally:

```bash
python examples/five_minute_demo.py
```

What it does:

1. Builds a wheel containing an executable `.pth` startup hook.
2. Adds import-time credential access and network exfiltration behaviour.
3. Copies the exact wheel into a quarantine directory by digest.
4. Runs the static scanner against the quarantined artefact.
5. Applies policy and denies the package.
6. Writes a review record showing no mirror promotion and no signed permit.

Example output:

```text
Palsy 5-minute demo: malicious package admission
1. Built malicious wheel: examples/artefacts/five-minute-demo/credential_stealer_demo-0.1.0-py3-none-any.whl
2. Quarantined exact artefact: examples/artefacts/five-minute-demo/quarantine/<sha256>.whl
3. Static scan max severity: critical
4. Policy decision: DENY
5. Review outcome: denied; no mirror promotion and no signed permit

Decision reasons:
- static scan maximum severity critical exceeds medium
- executable .pth startup hook is not allowlisted
- upstream upload timestamp is unavailable
- package has sensitive import-time behaviour
- artefact references network behaviour
```

Why this lands commercially:

- it is not a CVE demo;
- it blocks install/import-time behaviour before CI trusts the package;
- it produces an auditable review record;
- denied artefacts do not reach the internal mirror;
- no signed permit means downstream builds have nothing to verify.
