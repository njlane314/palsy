# Commercial Brand

Use **IngressShield** as the commercial product brand.

Keep `palsy` as the open-source package, CLI, and repository name until a migration is
worth the compatibility cost. The commercial site, sales material, paid plans, and buyer
conversations should lead with IngressShield.

## Category

```text
Package-ingress firewall for software supply chains.
```

## Primary Claim

```text
Block unapproved PyPI/npm packages before they enter CI.
```

## Positioning

IngressShield is a self-hosted package firewall that prevents unapproved PyPI/npm
artefacts from entering CI or production. It turns dependency installation into an
admission-control process: quarantine, scan, approve, mirror, and sign.

Use this framing before broader language such as "software supply-chain firewall".

## Buyer Wedge

Self-hosted dependency admission for Python-heavy teams that need enforceable package
approval evidence, not just alerts.

## Naming Rules

- Use **IngressShield** for the paid product.
- Use **Palsy** for the open-source engine and CLI.
- Use **Palsy Gate** only when referring to the root GitHub Action or local CI command.
- Avoid leading with "generic open-source library" language.
- Avoid "another SCA scanner"; the distinction is admission control plus signed permits.

## Short Description

IngressShield blocks unapproved PyPI/npm packages before they enter CI, then emits signed
permits so builds can prove which dependency graph was admitted under policy.
