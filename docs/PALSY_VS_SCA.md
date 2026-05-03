# Palsy vs SCA Scanners

Palsy is not another CVE alerting tool.

Traditional SCA scanners answer:

```text
Which dependencies have known vulnerabilities or licence issues?
```

Palsy answers:

```text
Is this exact package artefact allowed to enter CI or production?
```

## The Difference

| Capability | SCA scanner | Palsy |
| --- | --- | --- |
| CVE and advisory matching | Primary workflow | Not the core workflow |
| Licence inventory | Common workflow | Possible through reports, not the wedge |
| Exact artefact quarantine | Usually outside the tool | Core control point |
| Static malware/risk signals before install | Sometimes | Core control point |
| Optional sandbox before promotion | Sometimes | Built into the admission flow |
| Internal mirror promotion | Rare | Promotes only admitted artefacts where supported |
| Signed build permits | Rare | Core evidence model |
| CI behaviour | Alert, warn, or fail policy | Admit or block the exact dependency graph |

## Why This Matters

Modern dependency attacks often happen before a CVE exists. A package can be new,
typosquatted, compromised, or malicious at install/import time. The problem is not only
knowing whether a dependency is vulnerable; it is controlling whether an unapproved
artefact can enter a trusted build path.

Palsy turns dependency installation into an admission-control loop:

```text
resolve -> quarantine -> verify hashes -> scan -> sandbox optionally -> apply policy
        -> promote allowed artefacts -> emit signed Ed25519 permit
```

That signed permit gives CI and deployment systems evidence that a specific lockfile and
specific artefact digests were admitted under a named policy.

## When to Use Both

Use SCA scanners for:

- CVE and advisory monitoring;
- licence policy;
- transitive dependency inventory;
- remediation prioritisation.

Use Palsy for:

- blocking unapproved PyPI/npm packages before CI;
- package-ingress governance for Python-heavy teams;
- signed evidence that a lockfile was admitted;
- self-hosted package approval where alerts are not enough.

## Commercial Wedge

The sharp position is:

```text
Self-hosted dependency admission for Python-heavy teams that need enforceable package
approval evidence, not just alerts.
```

This maps to CI/CD dependency-chain abuse and artefact-integrity controls better than to
ordinary vulnerability scanning.

## References

- OWASP CI/CD Security Risk: Dependency Chain Abuse:
  <https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse>
- SLSA supply-chain integrity and provenance framework: <https://slsa.dev/>
