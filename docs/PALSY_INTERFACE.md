# Palsy Interface Layer

Palsy's product surface is the dependency-admission interface, not raw JSON. Every lockfile admission run can emit a local interface bundle under `.palsy/`:

```text
.palsy/
  admission.json
  dependency-passport.html
  summary.md
```

`admission.json` is the canonical renderer-neutral document. The static report, Markdown summary, and local console all read from this same object.

## Palsy Passport

Run a lockfile through the local gate and emit the static report:

```bash
palsy gate requirements.txt \
  --project demo-app \
  --environment ci \
  --html .palsy/dependency-passport.html
```

The report contains:

- build admission status and permit information;
- dependency diff;
- Explain This Decision cards;
- Artefact Autopsy cards;
- full inventory with decisions, severities, digests, and reasons.

## Palsy Console

Open the same result in the local console:

```bash
palsy console .palsy/admission.json
```

The console is intentionally local and does not require a hosted service.

## Policy Composer

Generate an opinionated policy without writing YAML by hand:

```bash
palsy policy compose --preset ci-balanced --non-interactive --force
```

This writes both:

```text
.palsy/policy.yaml
.palsy/policy.explained.md
```

The explanation file is intended for developers and reviewers who need to know why a build was admitted, held, or denied.
