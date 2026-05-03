from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from textwrap import dedent
from typing import Any

from .admission_output import format_admission_summary
from .interface_outputs import emit_report_bundle, safe_lockfile_stem
from .licensing import licence_status, load_licence
from .models import BuildPermit, Decision, Environment, LockfileAssessmentRequest
from .permits import verify_build_permit_document
from .service import FirewallService
from .settings import Settings
from .utils import sha256_bytes, utcnow


DEFAULT_POLICY = """
name: palsy-gate-default
mode: enforce
minimum_release_age_seconds:
  default: 86400
  dev: 0
  ci: 3600
  prod: 86400
allow_pth_exec:
  - setuptools
  - pip
allow_native_code:
  - numpy
  - scipy
  - cryptography
  - pillow
  - torch
  - tensorflow
allow_import_network:
  - certifi
allow_hidden_runtime: []
allow_lifecycle_scripts: []
allow_embedded_interpreter: []
trusted_publishers: {}
max_allowed_severity: medium
review_on_severity: high
permit_ttl_seconds: 604800
require_sandbox_for_prod: true
deny_oci_mutable_tags_in_prod: true
review_oci_mutable_tags_in_ci: true
require_expected_digest_for_generic_prod: true
""".lstrip()


GITHUB_WORKFLOW = """
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
          permit-out: .palsy/permits
""".lstrip()


GITLAB_CI = """
palsy-dependency-gate:
  image: python:3.12-slim
  stage: test
  before_script:
    - python -m pip install git+https://github.com/njlane314/palsy.git
  script:
    - palsy gate --mode enforce --environment ci --policy .palsy/policy.yaml --permit-out .palsy/permits
  artifacts:
    when: always
    paths:
      - .palsy/permits/
""".lstrip()


PALSY_GITIGNORE = """
state/
permits/
reports/
""".lstrip()


def init_command(args: argparse.Namespace) -> int:
    root = args.directory.resolve()
    palsy_dir = root / ".palsy"
    palsy_dir.mkdir(parents=True, exist_ok=True)

    written: list[Path] = []
    skipped: list[Path] = []

    _write_if_allowed(palsy_dir / "policy.yaml", DEFAULT_POLICY, args.force, written, skipped)
    _write_if_allowed(palsy_dir / ".gitignore", PALSY_GITIGNORE, args.force, written, skipped)

    if args.github_actions:
        _write_if_allowed(
            root / ".github" / "workflows" / "palsy.yml",
            GITHUB_WORKFLOW,
            args.force,
            written,
            skipped,
        )
    if args.gitlab_ci:
        _write_if_allowed(root / ".gitlab-ci-palsy.yml", GITLAB_CI, args.force, written, skipped)

    print("Palsy Gate initialised")
    for path in written:
        print(f"created: {_relative(path, root)}")
    for path in skipped:
        print(f"exists:  {_relative(path, root)} (use --force to overwrite)")
    print("\nStart in observe mode:")
    print("  palsy gate --mode observe")
    print("\nThen enforce in CI:")
    print("  palsy gate --mode enforce")
    return 0


def gate_command(args: argparse.Namespace) -> int:
    lockfiles = _select_lockfiles(args.lockfile)
    if not lockfiles:
        print(
            "no lockfiles found; pass requirements*.txt or package-lock.json explicitly",
            file=sys.stderr,
        )
        return 2

    for lockfile in lockfiles:
        if not lockfile.is_file():
            print(f"lockfile not found: {lockfile}", file=sys.stderr)
            return 2

    if getattr(args, "licence", None):
        licence_code = _check_gate_licence(
            args.licence,
            json_output=getattr(args, "json_output", False),
        )
        if licence_code:
            return licence_code

    settings = _settings_from_args(args)
    service = FirewallService(settings)

    try:
        responses = asyncio.run(_assess_lockfiles(service, args, lockfiles))
    except ValueError as exc:
        print(f"palsy gate failed: {exc}", file=sys.stderr)
        return 2

    payloads = [response.model_dump(mode="json") for response in responses]
    payload: dict[str, Any] | list[dict[str, Any]] = payloads[0] if len(payloads) == 1 else payloads

    report_paths: list[dict[str, Path]] = []
    if not args.no_report:
        if len(payloads) > 1 and (args.out or args.html or args.summary):
            print(
                "explicit --out, --html, and --summary support one lockfile; use --report-dir for multiple lockfiles",
                file=sys.stderr,
            )
            return 2
        for result in payloads:
            if len(payloads) == 1:
                paths = emit_report_bundle(
                    result,
                    report_dir=args.report_dir,
                    out=args.out,
                    html=args.html,
                    summary=args.summary,
                    baseline=args.baseline,
                    no_report=args.no_report,
                )
            else:
                stem = safe_lockfile_stem(str(result.get("lockfile_name") or "lockfile"))
                paths = emit_report_bundle(
                    result,
                    report_dir=args.report_dir,
                    out=args.report_dir / f"{stem}.admission.json",
                    html=args.report_dir / f"{stem}.dependency-passport.html",
                    summary=args.report_dir / f"{stem}.summary.md",
                    baseline=args.baseline,
                    no_report=args.no_report,
                )
            if paths:
                report_paths.append(paths)

    if args.json_output:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for index, result in enumerate(payloads):
            if index:
                print("\n" + "-" * 72 + "\n")
            print(format_admission_summary(result))
            if index < len(report_paths):
                print("\nPalsy interface outputs:")
                for label, path in report_paths[index].items():
                    print(f"- {label}: {path}")

    for response in responses:
        if response.permit:
            permit_path = _permit_output_path(args.permit_out, response.lockfile_name, len(responses) > 1)
            _write_json(permit_path, response.permit.model_dump(mode="json"))
            if not args.json_output:
                print(f"\nWrote build permit: {permit_path}")

    if args.mode == "observe":
        return 0
    return 0 if all(response.decision == Decision.allow for response in responses) else 1


def verify_permit_command(args: argparse.Namespace) -> int:
    if not args.permit.is_file():
        print(f"permit not found: {args.permit}", file=sys.stderr)
        return 2
    if not args.lockfile.is_file():
        print(f"lockfile not found: {args.lockfile}", file=sys.stderr)
        return 2

    try:
        data = json.loads(args.permit.read_text(encoding="utf-8"))
        permit = BuildPermit.model_validate(data)
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"invalid build permit: {exc}", file=sys.stderr)
        return 2

    errors = _permit_errors(permit, args)
    if errors:
        for error in errors:
            print(f"permit verification failed: {error}", file=sys.stderr)
        return 1

    print(f"Build permit verified: {permit.id}")
    print(f"Project: {permit.subject.project}")
    print(f"Lockfile: {permit.subject.lockfile_name}")
    print(f"Lockfile digest: {permit.subject.lockfile_digest}")
    print(f"Environment: {permit.environment.value}")
    print(f"Expires: {permit.expires_at.isoformat()}")
    return 0


def _check_gate_licence(path: Path, *, json_output: bool = False) -> int:
    stream = sys.stderr if json_output else sys.stdout
    if not path.is_file():
        print(f"licence not found: {path}", file=sys.stderr)
        return 2
    try:
        licence = load_licence(path)
    except OSError as exc:
        print(f"licence could not be read: {exc}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"licence is not valid JSON: {exc}", file=sys.stderr)
        return 2

    status = licence_status(licence)
    if status["state"] != "active":
        print(
            f"licence check failed: {status['state']} ({status.get('reason', 'unknown reason')})",
            file=sys.stderr,
        )
        return 1

    print(
        f"Palsy licence active: {status.get('plan') or 'unknown plan'}, "
        f"{status['days_remaining']} days remaining",
        file=stream,
    )
    return 0


async def _assess_lockfiles(
    service: FirewallService,
    args: argparse.Namespace,
    lockfiles: list[Path],
):
    responses = []
    for lockfile in lockfiles:
        request = LockfileAssessmentRequest(
            project=args.project or Path.cwd().name,
            lockfile_name=str(lockfile),
            content=lockfile.read_text(encoding="utf-8"),
            environment=Environment(args.environment),
            sandbox=args.sandbox,
            force_rescan=args.force_rescan,
        )
        responses.append(await service.assess_lockfile(request))
    return responses


def _settings_from_args(args: argparse.Namespace) -> Settings:
    policy = args.policy
    default_policy = Path(".palsy/policy.yaml")
    if policy is None and default_policy.exists():
        policy = default_policy

    state_dir = args.state_dir or Path(".palsy/state")
    return Settings(state_dir=state_dir, policy_file=policy)


def _select_lockfiles(explicit: list[Path]) -> list[Path]:
    if explicit:
        return explicit
    candidates: list[Path] = []
    candidates.extend(sorted(Path.cwd().glob("requirements*.txt")))
    package_lock = Path("package-lock.json")
    if package_lock.exists():
        candidates.append(package_lock)
    return _dedupe_paths(candidates)


def _dedupe_paths(paths: list[Path]) -> list[Path]:
    seen: set[Path] = set()
    unique: list[Path] = []
    for path in paths:
        key = path.resolve()
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)
    return unique


def _permit_errors(permit: BuildPermit, args: argparse.Namespace) -> list[str]:
    errors: list[str] = []
    if not verify_build_permit_document(permit):
        errors.append("signature is invalid")
    if permit.decision != Decision.allow:
        errors.append(f"decision is {permit.decision.value}, not allow")
    if permit.expires_at < utcnow():
        errors.append(f"permit expired at {permit.expires_at.isoformat()}")
    if args.project and permit.subject.project != args.project:
        errors.append(f"project mismatch: permit has {permit.subject.project!r}")
    if args.environment and permit.environment != Environment(args.environment):
        errors.append(f"environment mismatch: permit has {permit.environment.value!r}")

    lockfile_digest = sha256_bytes(args.lockfile.read_bytes())
    if permit.subject.lockfile_digest != lockfile_digest:
        errors.append("lockfile digest does not match permit subject")
    permit_lockfile = Path(permit.subject.lockfile_name)
    if permit_lockfile.name != args.lockfile.name and permit.subject.lockfile_name != str(args.lockfile):
        errors.append(f"lockfile name mismatch: permit has {permit.subject.lockfile_name!r}")
    return errors


def _permit_output_path(base: Path, lockfile_name: str, multiple: bool) -> Path:
    if base.suffix == ".json" and not multiple:
        return base
    safe_name = lockfile_name.replace("/", "_").replace("\\", "_")
    return base / f"{safe_name}.permit.json"


def _write_if_allowed(
    path: Path,
    content: str,
    force: bool,
    written: list[Path],
    skipped: list[Path],
) -> None:
    if path.exists() and not force:
        skipped.append(path)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dedent(content), encoding="utf-8")
    written.append(path)


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _relative(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)
