from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request


def main() -> int:
    base_url = os.environ.get("PALSY_URL", "http://127.0.0.1:8080").rstrip("/")
    token = os.environ.get("PALSY_API_TOKEN")
    project = os.environ.get("PALSY_EXAMPLE_PROJECT", "idna")
    version = os.environ.get("PALSY_EXAMPLE_VERSION", "3.10")

    if not token:
        print("PALSY_API_TOKEN is required because protected API endpoints require authentication.", file=sys.stderr)
        return 2

    payload = json.dumps(
        {
            "project": project,
            "version": version,
            "environment": os.environ.get("PALSY_ENVIRONMENT", "ci"),
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        f"{base_url}/v1/artifacts/pypi/assess",
        data=payload,
        headers={"Content-Type": "application/json", "X-API-Token": token},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            result = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        print(exc.read().decode("utf-8", errors="replace"), file=sys.stderr)
        return 1

    policy = result["policy"]
    print(f"package: {project}=={version}")
    print(f"decision: {policy['decision']}")
    print(f"digest: {result['digest']}")
    print("reasons:")
    for reason in policy.get("reasons", []):
        print(f"  - {reason}")
    if result.get("permit"):
        print(f"permit: {result['permit']['id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
