# Monetisation Plan

Sell **IngressShield** as the commercial brand for the Palsy open-source engine.

IngressShield should sell a narrow outcome first:

```text
Block unapproved PyPI/npm packages before they enter CI.
```

The open-source repository proves the gate. The paid product packages policy updates,
commercial support, private bundles, and self-hosted governance around that gate. Keep
`No permit, no build.` as a secondary slogan after the buyer understands the concrete CI
control.

## Market Narrative

The commercial story is live: package registries are an active malware ingress path, not
only a vulnerability-management backlog. Sonatype's Q1 2026 Open Source Malware Index
reported 21,764 malicious open-source packages in the quarter, with PyPI representing
18% of that quarter's malware volume.

Do not lead with "we scan packages." Lead with the control loop:

```text
quarantine -> scan -> approve -> mirror -> sign
```

That maps Palsy to CI/CD dependency-chain abuse and artefact-integrity controls, and to
SLSA-style supply-chain evidence, more naturally than to ordinary SCA alerting.

## Self-Serve Offer

Community:

- local scans and lockfile admission;
- signed build permits;
- JSON, HTML, and Markdown reports;
- public documentation and examples.

IngressShield Team:

- GBP 199/month or GBP 1,999/year;
- CI enforcement bundle;
- private policy/update bundle;
- policy templates with explained defaults;
- commercial Docker images and release support.

IngressShield Business:

- GBP 999/month or GBP 9,999/year;
- self-hosted API server;
- PyPI/npm mirror surfaces;
- review queue, revocations, Postgres, audit exports;
- Slack, Jira, or GitHub issue automation.

## Stripe Payment Links

Stripe Payment Links are the quickest checkout path because they can sell a product or
subscription through a Stripe-hosted page with low integration effort.

Create these Stripe products and prices:

- `IngressShield Team Monthly`, recurring, `GBP 199/month`;
- `IngressShield Team Annual`, recurring, `GBP 1,999/year`;
- `IngressShield Business Monthly`, recurring, `GBP 999/month`;
- `IngressShield Business Annual`, recurring, `GBP 9,999/year`.

Then replace the placeholder links in [docs/index.html](index.html):

```text
https://buy.stripe.com/replace_ingressshield_team_monthly
https://buy.stripe.com/replace_ingressshield_business_monthly
```

Recommended Stripe settings:

- require business email and billing address;
- collect tax details where needed;
- enable promotion codes only for controlled pilots;
- redirect successful purchases to the trial fulfilment instructions;
- include the buyer email in the private licence/policy bundle workflow.

Reference: <https://docs.stripe.com/payment-links>

## Fourteen-Day Trial

Palsy now has a local trial licence command:

```bash
palsy licence trial --email buyer@example.com --out .palsy/licence.json
palsy licence check --licence .palsy/licence.json
palsy gate requirements.txt --mode enforce --licence .palsy/licence.json
```

The generated file is a simple self-serve licence scaffold. It is suitable for early
commercial packaging, pilots, and private policy/update bundles. It is not a
cryptographic billing enforcement system. When `--licence` is supplied, `palsy gate`
checks that the licence is active before admitting the lockfile.

Trial fulfilment flow:

1. The buyer asks for a trial or clicks a trial call-to-action.
2. Generate `.palsy/licence.json` for the buyer email.
3. Send the licence with a private policy/update bundle or private container image.
4. Tell the buyer to pass `--licence .palsy/licence.json` or the GitHub Action `licence`
   input in their CI workflow.
5. After 14 days, convert the buyer to the Stripe subscription.
6. For paid users, send renewed private bundle access through your chosen fulfilment process.

## Public Action Release

The GitHub Action lives at the repository root as [action.yml](../action.yml). To publish it
properly:

- make the repository public only after reviewing the public release checklist;
- tag stable releases such as `v0.3.0`;
- tell customers to pin `uses: njlane314/palsy@v0.3.0`, not `@main`;
- enable GitHub Pages from `/docs` so [docs/index.html](index.html) becomes the public
  landing page.

## GitHub Marketplace Later

The first paid path should be Stripe because it avoids building GitHub Marketplace billing
webhook handling before there is demand. Later, list Palsy as a GitHub App or Action once
the fulfilment flow is stable.

Marketplace notes to preserve:

- GitHub Marketplace app listings support up to 10 pricing plans.
- Paid plans require publisher verification.
- Marketplace paid plans need monthly and annual prices.
- If a paid service is sold outside Marketplace, avoid a misleading free-only Marketplace
  listing.
- Marketplace free trials are 14 days and need the required purchase, cancellation, and plan
  change handling.

Reference:
<https://docs.github.com/en/apps/github-marketplace/selling-your-app-on-github-marketplace/pricing-plans-for-github-marketplace-apps>

Additional references:

- Sonatype Q1 2026 Open Source Malware Index:
  <https://www.sonatype.com/press-releases/sonatype-q1-2026-open-source-malware-index>
- OWASP Dependency Chain Abuse:
  <https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse>
- SLSA: <https://slsa.dev/>
