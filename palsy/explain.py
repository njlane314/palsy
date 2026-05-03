from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class RuleExplanation:
    title: str
    severity: str
    why: str
    fix: str
    policy_hint: str | None = None


EXPLANATION_PATTERNS: tuple[tuple[str, RuleExplanation], ...] = (
    (
        "executable .pth startup hook",
        RuleExplanation(
            title="Executable Python startup hook",
            severity="high",
            why=(
                "Python .pth files can execute during interpreter startup, before normal "
                "application code, tests, and runtime controls are active."
            ),
            fix=(
                "Remove the dependency, choose a safer version, or add the package to "
                "allow_pth_exec only after reviewing the exact artefact digest."
            ),
            policy_hint="allow_pth_exec",
        ),
    ),
    (
        "startup hook",
        RuleExplanation(
            title="Python startup hook",
            severity="high",
            why=(
                "sitecustomize.py and usercustomize.py are imported automatically by Python "
                "in many environments, so a dependency can run code without an explicit import."
            ),
            fix="Review the file contents and remove the dependency or approve the exact digest.",
        ),
    ),
    (
        "npm install/lifecycle script",
        RuleExplanation(
            title="npm lifecycle script",
            severity="medium",
            why=(
                "npm lifecycle scripts can execute shell commands during install, often before "
                "the application is built while CI secrets and network access may be available."
            ),
            fix=(
                "Prefer packages without install scripts. If the script is expected, allowlist "
                "the package and keep the approval tied to the artefact digest."
            ),
            policy_hint="allow_lifecycle_scripts",
        ),
    ),
    (
        "native code",
        RuleExplanation(
            title="Native code present",
            severity="medium",
            why=(
                "Native extensions and binaries are harder to inspect than source-only packages "
                "and can execute platform-specific behaviour during import or runtime."
            ),
            fix="Review the package provenance and add it to allow_native_code only if expected.",
            policy_hint="allow_native_code",
        ),
    ),
    (
        "embedded secondary interpreter",
        RuleExplanation(
            title="Embedded secondary runtime",
            severity="high",
            why=(
                "Bundled runtimes such as Node, Deno, Bun, or other interpreters increase the "
                "amount of executable code admitted into the build."
            ),
            fix="Remove the package or explicitly approve the embedded runtime after manual review.",
            policy_hint="allow_embedded_interpreter",
        ),
    ),
    (
        "hidden/runtime staging directory",
        RuleExplanation(
            title="Hidden runtime staging directory",
            severity="high",
            why=(
                "Hidden runtime directories can stage executable payloads or helper tools that "
                "are not obvious from the package's public API."
            ),
            fix="Inspect the staged files and approve only if the runtime payload is legitimate.",
            policy_hint="allow_hidden_runtime",
        ),
    ),
    (
        "references network behaviour",
        RuleExplanation(
            title="Network behaviour reference",
            severity="medium",
            why=(
                "Network references can be benign, but they matter during dependency admission "
                "because CI often has outbound network access and credentials."
            ),
            fix="Review whether network access is expected and allowlist only known-safe packages.",
            policy_hint="allow_import_network",
        ),
    ),
    (
        "mutable tag",
        RuleExplanation(
            title="Mutable OCI reference",
            severity="high",
            why=(
                "Mutable image tags can point to different content over time. Admission needs "
                "to bind to immutable digests so the build consumes reviewed content."
            ),
            fix="Use an OCI digest reference such as image@sha256:... for production builds.",
            policy_hint="deny_oci_mutable_tags_in_prod",
        ),
    ),
    (
        "no caller-supplied expected digest",
        RuleExplanation(
            title="Generic artefact without expected digest",
            severity="high",
            why=(
                "Generic URLs do not provide registry-level package identity. A caller-supplied "
                "digest is the minimum binding for reproducible admission."
            ),
            fix="Provide expected_digest for generic production artefacts.",
            policy_hint="require_expected_digest_for_generic_prod",
        ),
    ),
    (
        "release age",
        RuleExplanation(
            title="Fresh release quarantine",
            severity="medium",
            why=(
                "Fresh package releases have had less time to be observed, mirrored, reported, "
                "or reviewed. Quarantine windows reduce exposure to fast-moving attacks."
            ),
            fix="Wait for the configured quarantine window or approve the exact digest after review.",
            policy_hint="minimum_release_age_seconds",
        ),
    ),
    (
        "static scan maximum severity",
        RuleExplanation(
            title="Static scan severity threshold",
            severity="high",
            why="The scanner found behaviour above the policy threshold for this environment.",
            fix="Inspect finding evidence, then remove the artefact or tune policy for known-safe packages.",
            policy_hint="max_allowed_severity",
        ),
    ),
)


def explain_reason(reason: str) -> dict[str, str | None]:
    normalized = reason.lower()
    for fragment, explanation in EXPLANATION_PATTERNS:
        if fragment in normalized:
            data = asdict(explanation)
            data["reason"] = reason
            return data
    return {
        "reason": reason,
        "title": "Policy decision",
        "severity": "info",
        "why": "This reason came from the active Palsy policy or dependency resolver.",
        "fix": "Inspect the artefact, policy, and dependency graph before approving the build.",
        "policy_hint": None,
    }


def explain_reasons(reasons: list[str]) -> list[dict[str, str | None]]:
    return [explain_reason(reason) for reason in reasons]
