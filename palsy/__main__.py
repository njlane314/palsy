from __future__ import annotations

import argparse
import json
from pathlib import Path

import uvicorn

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

    args = parser.parse_args()
    if args.command in {None, "serve"}:
        settings = get_settings()
        uvicorn.run("palsy.api:app", host=args.host or settings.host, port=args.port or settings.port)
    elif args.command == "scan":
        digest = sha256_file(args.artifact)
        report = StaticArtifactScanner().scan(args.artifact, digest=digest)
        print(json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
