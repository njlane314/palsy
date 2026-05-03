from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import secrets
from typing import Any


LICENCE_SCHEMA = "palsy-licence/v1"
DEFAULT_TRIAL_DAYS = 14


def create_trial_licence(
    email: str,
    *,
    days: int = DEFAULT_TRIAL_DAYS,
    plan: str = "team-trial",
    now: datetime | None = None,
) -> dict[str, Any]:
    if days <= 0:
        raise ValueError("trial length must be at least one day")
    customer_email = email.strip().lower()
    if "@" not in customer_email:
        raise ValueError("a valid email address is required")

    issued_at = _normalise_datetime(now or datetime.now(timezone.utc))
    expires_at = issued_at + timedelta(days=days)
    return {
        "schema": LICENCE_SCHEMA,
        "kind": "local-trial",
        "plan": plan,
        "email": customer_email,
        "issued_at": _format_datetime(issued_at),
        "expires_at": _format_datetime(expires_at),
        "features": [
            "ci-gate",
            "signed-build-permits",
            "policy-templates",
            "interface-reports",
        ],
        "licence_key": f"palsy_trial_{secrets.token_urlsafe(24)}",
        "issuer": "self-serve",
    }


def write_licence(path: Path, licence: dict[str, Any], *, force: bool = False) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"licence already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(licence, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_licence(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def licence_status(
    licence: dict[str, Any],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    current_time = _normalise_datetime(now or datetime.now(timezone.utc))
    if licence.get("schema") != LICENCE_SCHEMA:
        return {
            "state": "invalid",
            "reason": "unsupported licence schema",
            "days_remaining": 0,
        }

    try:
        expires_at = _parse_datetime(str(licence["expires_at"]))
    except (KeyError, ValueError):
        return {
            "state": "invalid",
            "reason": "missing or invalid expiry",
            "days_remaining": 0,
        }

    remaining = expires_at - current_time
    if remaining.total_seconds() <= 0:
        return {
            "state": "expired",
            "reason": "licence has expired",
            "days_remaining": 0,
            "expires_at": _format_datetime(expires_at),
            "plan": licence.get("plan"),
            "email": licence.get("email"),
        }

    days_remaining = int((remaining.total_seconds() + 86399) // 86400)
    return {
        "state": "active",
        "reason": "licence is active",
        "days_remaining": days_remaining,
        "expires_at": _format_datetime(expires_at),
        "plan": licence.get("plan"),
        "email": licence.get("email"),
    }


def _normalise_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _format_datetime(value: datetime) -> str:
    return _normalise_datetime(value).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_datetime(value: str) -> datetime:
    return _normalise_datetime(datetime.fromisoformat(value.replace("Z", "+00:00")))
