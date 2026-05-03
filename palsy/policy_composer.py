from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


PRESETS = ("dev-relaxed", "ci-balanced", "prod-strict")


def policy_from_preset(preset: str = "ci-balanced", *, environment: str = "ci") -> dict[str, Any]:
    if preset not in PRESETS:
        raise ValueError(f"unknown policy preset {preset!r}; choose one of {', '.join(PRESETS)}")
    if preset == "dev-relaxed":
        return {
            "name": "palsy-dev-relaxed",
            "mode": "warn",
            "minimum_release_age_seconds": {"default": 0, "dev": 0, "ci": 0, "prod": 86400},
            "allow_pth_exec": ["pip", "setuptools"],
            "allow_native_code": ["numpy", "scipy", "cryptography", "pillow"],
            "allow_import_network": ["certifi"],
            "allow_hidden_runtime": [],
            "allow_lifecycle_scripts": [],
            "allow_embedded_interpreter": [],
            "trusted_publishers": {},
            "max_allowed_severity": "high",
            "review_on_severity": "high",
            "permit_ttl_seconds": 604800,
            "require_sandbox_for_prod": True,
            "deny_oci_mutable_tags_in_prod": True,
            "review_oci_mutable_tags_in_ci": True,
            "require_expected_digest_for_generic_prod": True,
        }
    if preset == "prod-strict":
        return {
            "name": "palsy-prod-strict",
            "mode": "enforce",
            "minimum_release_age_seconds": {"default": 172800, "dev": 0, "ci": 86400, "prod": 172800},
            "allow_pth_exec": ["pip", "setuptools"],
            "allow_native_code": ["numpy", "scipy", "cryptography", "pillow", "torch", "tensorflow"],
            "allow_import_network": ["certifi"],
            "allow_hidden_runtime": [],
            "allow_lifecycle_scripts": [],
            "allow_embedded_interpreter": [],
            "trusted_publishers": {},
            "max_allowed_severity": "medium",
            "review_on_severity": "medium",
            "permit_ttl_seconds": 604800,
            "require_sandbox_for_prod": True,
            "deny_oci_mutable_tags_in_prod": True,
            "review_oci_mutable_tags_in_ci": True,
            "require_expected_digest_for_generic_prod": True,
        }
    return {
        "name": "palsy-ci-balanced",
        "mode": "enforce" if environment in {"ci", "prod"} else "warn",
        "minimum_release_age_seconds": {"default": 86400, "dev": 0, "ci": 3600, "prod": 86400},
        "allow_pth_exec": ["pip", "setuptools"],
        "allow_native_code": ["numpy", "scipy", "cryptography", "pillow", "torch", "tensorflow"],
        "allow_import_network": ["certifi"],
        "allow_hidden_runtime": [],
        "allow_lifecycle_scripts": [],
        "allow_embedded_interpreter": [],
        "trusted_publishers": {},
        "max_allowed_severity": "medium",
        "review_on_severity": "high",
        "permit_ttl_seconds": 604800,
        "require_sandbox_for_prod": True,
        "deny_oci_mutable_tags_in_prod": True,
        "review_oci_mutable_tags_in_ci": True,
        "require_expected_digest_for_generic_prod": True,
    }


def write_policy(path: Path, policy: dict[str, Any], *, force: bool = False) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"policy file already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(policy, sort_keys=False), encoding="utf-8")


def write_policy_explanation(path: Path, policy: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(policy_explanation(policy), encoding="utf-8")


def policy_explanation(policy: dict[str, Any]) -> str:
    age = policy.get("minimum_release_age_seconds", {})
    lines = [
        f"# {policy.get('name', 'Palsy policy')}",
        "",
        f"Mode: `{policy.get('mode')}`",
        "",
        "This policy:",
        f"- reviews or blocks fresh releases using thresholds {age};",
        "- denies executable Python .pth startup hooks unless the package is allowlisted;",
        "- reviews npm lifecycle scripts unless the package is allowlisted;",
        "- reviews native code unless the package is allowlisted;",
        "- denies mutable OCI tags in production when configured;",
        "- requires expected digests for generic production artefacts when configured;",
        "- issues signed permits only for admitted dependency graphs.",
        "",
        "Operational rule: no permit, no build.",
    ]
    return "\n".join(lines)


def compose_policy_interactive(*, preset: str | None, environment: str, out: Path, force: bool) -> dict[str, Any]:
    selected = preset or _prompt_choice("Choose a policy preset", PRESETS, default="ci-balanced")
    policy = policy_from_preset(selected, environment=environment)
    write_policy(out, policy, force=force)
    write_policy_explanation(out.with_suffix(".explained.md"), policy)
    return policy


def _prompt_choice(label: str, choices: tuple[str, ...], *, default: str) -> str:
    print(label)
    for index, choice in enumerate(choices, start=1):
        marker = "*" if choice == default else " "
        print(f"  {index}. {choice} {marker}")
    raw = input(f"Selection [{default}]: ").strip()
    if not raw:
        return default
    if raw.isdigit():
        idx = int(raw) - 1
        if 0 <= idx < len(choices):
            return choices[idx]
    if raw in choices:
        return raw
    raise ValueError(f"invalid selection: {raw}")
