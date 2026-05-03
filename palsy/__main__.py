from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import urllib.error
import urllib.request

import uvicorn

from .admission_report import load_admission_document
from .admission_output import format_admission_summary
from .gate import gate_command, init_command, verify_permit_command
from .interface_outputs import emit_report_bundle, write_rendered_outputs
from .policy_composer import (
    compose_policy_interactive,
    policy_explanation,
    policy_from_preset,
    write_policy,
    write_policy_explanation,
)
from .scanner import StaticArtifactScanner
from .settings import get_settings
from .utils import sha256_file


def main() -> None:
    parser = argparse.ArgumentParser(prog="palsy", description="Palsy")
    sub = parser.add_subparsers(dest="command")

    serve = sub.add_parser("serve", help="Run the HTTP API")
    serve.add_argument("--host", default=None)
    serve.add_argument("--port", type=int, default=None)

    scan = sub.add_parser("scan", help="Statically scan a local wheel or sdist")
    scan.add_argument("artifact", type=Path, metavar="artefact")

    init = sub.add_parser(
        "init",
        help="Bootstrap a self-serve Palsy Gate policy and CI workflow",
    )
    init.add_argument("--directory", type=Path, default=Path.cwd())
    init.add_argument("--force", action="store_true", help="Overwrite generated files")
    init.add_argument(
        "--github-actions",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Write .github/workflows/palsy.yml",
    )
    init.add_argument(
        "--gitlab-ci",
        action="store_true",
        help="Write .gitlab-ci-palsy.yml",
    )

    gate = sub.add_parser(
        "gate",
        help="Assess lockfiles locally and optionally fail CI unless they are admitted",
    )
    gate.add_argument("lockfile", type=Path, nargs="*", help="Lockfiles to assess")
    gate.add_argument("--project", default=None)
    gate.add_argument(
        "--environment",
        choices=["dev", "ci", "prod"],
        default=os.environ.get("PALSY_ENVIRONMENT", "ci"),
    )
    gate.add_argument(
        "--mode",
        choices=["observe", "enforce"],
        default=os.environ.get("PALSY_GATE_MODE", "observe"),
        help="observe exits 0 after reporting; enforce exits non-zero for review/deny",
    )
    gate.add_argument("--policy", type=Path, default=None)
    gate.add_argument("--state-dir", type=Path, default=None)
    gate.add_argument("--sandbox", action="store_true")
    gate.add_argument("--force-rescan", action="store_true")
    gate.add_argument("--json", action="store_true", dest="json_output")
    gate.add_argument("--out", type=Path, default=None, help="Write canonical admission JSON")
    _add_report_args(gate, include_out=False)
    gate.add_argument(
        "--permit-out",
        type=Path,
        default=Path(".palsy/permits"),
        help="Directory or file path for signed build permits",
    )

    verify = sub.add_parser("verify-permit", help="Verify a signed Palsy build permit")
    verify.add_argument("permit", type=Path)
    verify.add_argument("--lockfile", type=Path, required=True)
    verify.add_argument("--project", default=None)
    verify.add_argument("--environment", choices=["dev", "ci", "prod"], default=None)

    admit_lockfile = sub.add_parser(
        "admit-lockfile",
        help="Assess a lockfile through the API and exit non-zero unless it is allowed",
    )
    admit_lockfile.add_argument("lockfile", type=Path)
    admit_lockfile.add_argument("--project", default=None)
    admit_lockfile.add_argument(
        "--environment",
        choices=["dev", "ci", "prod"],
        default=os.environ.get("PALSY_ENVIRONMENT", "ci"),
    )
    admit_lockfile.add_argument("--url", default=os.environ.get("PALSY_URL", "http://127.0.0.1:8080"))
    admit_lockfile.add_argument("--token", default=os.environ.get("PALSY_API_TOKEN"))
    admit_lockfile.add_argument("--sandbox", action="store_true")
    admit_lockfile.add_argument("--force-rescan", action="store_true")
    admit_lockfile.add_argument("--timeout", type=int, default=300)
    admit_lockfile.add_argument("--json", action="store_true", dest="json_output")
    _add_report_args(admit_lockfile)

    report = sub.add_parser("report", help="Render an admission.json file into user-facing outputs")
    report.add_argument("admission", type=Path, help="admission.json or raw lockfile assessment JSON")
    report.add_argument("--html", type=Path, default=Path(".palsy/dependency-passport.html"))
    report.add_argument("--summary", type=Path, default=Path(".palsy/summary.md"))

    console = sub.add_parser("console", help="Open the local Palsy Console TUI")
    console.add_argument("admission", type=Path, nargs="?", default=Path(".palsy/admission.json"))

    policy = sub.add_parser("policy", help="Policy tools")
    policy_sub = policy.add_subparsers(dest="policy_command")
    policy_sub.required = True
    compose = policy_sub.add_parser("compose", help="Generate a policy through the Policy Composer")
    compose.add_argument("--out", type=Path, default=Path(".palsy/policy.yaml"))
    compose.add_argument("--preset", choices=["dev-relaxed", "ci-balanced", "prod-strict"], default=None)
    compose.add_argument("--environment", choices=["dev", "ci", "prod"], default="ci")
    compose.add_argument("--force", action="store_true")
    compose.add_argument("--non-interactive", action="store_true")

    args = parser.parse_args()
    if args.command in {None, "serve"}:
        settings = get_settings()
        uvicorn.run("palsy.api:app", host=args.host or settings.host, port=args.port or settings.port)
    elif args.command == "scan":
        digest = sha256_file(args.artifact)
        report = StaticArtifactScanner().scan(args.artifact, digest=digest)
        print(json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True))
    elif args.command == "init":
        raise SystemExit(init_command(args))
    elif args.command == "gate":
        raise SystemExit(gate_command(args))
    elif args.command == "verify-permit":
        raise SystemExit(verify_permit_command(args))
    elif args.command == "admit-lockfile":
        raise SystemExit(admit_lockfile_command(args))
    elif args.command == "report":
        raise SystemExit(report_command(args))
    elif args.command == "console":
        from .console import run_console

        raise SystemExit(run_console(args.admission))
    elif args.command == "policy" and args.policy_command == "compose":
        raise SystemExit(policy_compose_command(args))


def _add_report_args(parser: argparse.ArgumentParser, *, include_out: bool = True) -> None:
    parser.add_argument("--report-dir", type=Path, default=Path(".palsy"))
    if include_out:
        parser.add_argument("--out", type=Path, default=None, help="Write canonical admission JSON")
    parser.add_argument("--html", type=Path, default=None, help="Write the static Palsy Passport report")
    parser.add_argument("--summary", type=Path, default=None, help="Write a Markdown summary")
    parser.add_argument("--baseline", type=Path, default=None, help="Previous admission JSON for Dependency Diff")
    parser.add_argument("--no-report", action="store_true", help="Do not write admission.json or reports")


def admit_lockfile_command(args: argparse.Namespace) -> int:
    if not args.lockfile.is_file():
        print(f"lockfile not found: {args.lockfile}", file=sys.stderr)
        return 2

    payload = {
        "project": args.project or Path.cwd().name,
        "lockfile_name": args.lockfile.name,
        "content": args.lockfile.read_text(encoding="utf-8"),
        "environment": args.environment,
        "sandbox": args.sandbox,
        "force_rescan": args.force_rescan,
    }
    headers = {"Content-Type": "application/json"}
    if args.token:
        headers["X-API-Token"] = args.token
    request = urllib.request.Request(
        f"{args.url.rstrip('/')}/v1/lockfiles/assess",
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=args.timeout) as response:
            result = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        print(detail, file=sys.stderr)
        return 2
    except urllib.error.URLError as exc:
        print(f"lockfile admission request failed: {exc}", file=sys.stderr)
        return 2

    report_paths = emit_report_bundle(
        result,
        report_dir=getattr(args, "report_dir", None),
        out=getattr(args, "out", None),
        html=getattr(args, "html", None),
        summary=getattr(args, "summary", None),
        baseline=getattr(args, "baseline", None),
        no_report=getattr(args, "no_report", False),
    )
    if args.json_output:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(format_admission_summary(result))
        if report_paths:
            print("\nPalsy interface outputs:")
            for label, path in report_paths.items():
                print(f"- {label}: {path}")
    return 0 if result.get("decision") == "allow" else 1


def report_command(args: argparse.Namespace) -> int:
    document = load_admission_document(args.admission)
    write_rendered_outputs(document, args.html, args.summary)
    print(f"HTML report: {args.html}")
    print(f"Markdown summary: {args.summary}")
    return 0


def policy_compose_command(args: argparse.Namespace) -> int:
    try:
        if args.non_interactive:
            policy = policy_from_preset(args.preset or "ci-balanced", environment=args.environment)
            write_policy(args.out, policy, force=args.force)
            write_policy_explanation(args.out.with_suffix(".explained.md"), policy)
        else:
            policy = compose_policy_interactive(
                preset=args.preset,
                environment=args.environment,
                out=args.out,
                force=args.force,
            )
    except FileExistsError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(f"Policy written: {args.out}")
    print(f"Explanation written: {args.out.with_suffix('.explained.md')}")
    print(policy_explanation(policy))
    return 0


if __name__ == "__main__":
    main()
