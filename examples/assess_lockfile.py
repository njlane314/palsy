from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path


def main() -> int:
    base_url = os.environ.get("PALSY_URL", "http://127.0.0.1:8080").rstrip("/")
    token = os.environ.get("PALSY_API_TOKEN")
    project = os.environ.get("PALSY_EXAMPLE_PROJECT", "demo-app")
    lockfile_path = os.environ.get("PALSY_LOCKFILE_PATH")
    lockfile_name = os.environ.get("PALSY_LOCKFILE_NAME", "requirements.txt")

    if not token:
        print("PALSY_API_TOKEN is required because protected API endpoints require authentication.", file=sys.stderr)
        return 2

    if lockfile_path:
        path = Path(lockfile_path)
        lockfile_name = path.name
        content = path.read_text(encoding="utf-8")
    else:
        content = os.environ.get("PALSY_LOCKFILE_CONTENT", "idna==3.10\npackaging==24.2\n")

    payload = json.dumps(
        {
            "project": project,
            "lockfile_name": lockfile_name,
            "content": content,
            "environment": os.environ.get("PALSY_ENVIRONMENT", "ci"),
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        f"{base_url}/v1/lockfiles/assess",
        data=payload,
        headers={"Content-Type": "application/json", "X-API-Token": token},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=300) as response:
            result = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        print(exc.read().decode("utf-8", errors="replace"), file=sys.stderr)
        return 1

    print(f"project: {result['project']}")
    print(f"lockfile: {result['lockfile_name']}")
    print(f"decision: {result['decision']}")
    print(f"lockfile digest: {result['lockfile_digest']}")
    print(f"dependencies: {result['dependency_count']}")
    print("reasons:")
    for reason in result.get("reasons", []):
        print(f"  - {reason}")
    for item in result.get("items", []):
        coordinate = item["coordinate"]
        name = coordinate.get("name") or coordinate.get("project")
        print(f"  {coordinate['ecosystem']}:{name}@{coordinate.get('version')} -> {item['decision']}")
    if result.get("permit"):
        print(f"build permit: {result['permit']['id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
