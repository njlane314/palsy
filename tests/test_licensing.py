from __future__ import annotations

import argparse
from datetime import datetime, timezone

import palsy.__main__ as cli
from palsy.licensing import create_trial_licence, licence_status, load_licence, write_licence


def test_create_trial_licence_sets_fourteen_day_expiry():
    now = datetime(2026, 1, 1, 9, 30, tzinfo=timezone.utc)

    licence = create_trial_licence("Buyer@Example.COM", now=now)
    status = licence_status(licence, now=now)

    assert licence["schema"] == "palsy-licence/v1"
    assert licence["kind"] == "local-trial"
    assert licence["email"] == "buyer@example.com"
    assert licence["expires_at"] == "2026-01-15T09:30:00Z"
    assert licence["licence_key"].startswith("palsy_trial_")
    assert status["state"] == "active"
    assert status["days_remaining"] == 14


def test_licence_status_marks_expired_trials():
    licence = create_trial_licence(
        "buyer@example.com",
        now=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    status = licence_status(licence, now=datetime(2026, 1, 16, tzinfo=timezone.utc))

    assert status["state"] == "expired"
    assert status["days_remaining"] == 0


def test_write_and_load_licence_round_trip(tmp_path):
    path = tmp_path / ".palsy" / "licence.json"
    licence = create_trial_licence("buyer@example.com")

    write_licence(path, licence)

    assert load_licence(path) == licence


def test_licence_trial_command_writes_file(tmp_path, capsys):
    path = tmp_path / ".palsy" / "licence.json"
    args = argparse.Namespace(email="buyer@example.com", out=path, days=14, force=False)

    code = cli.licence_trial_command(args)

    assert code == 0
    assert path.is_file()
    output = capsys.readouterr().out
    assert "Trial licence written:" in output
    assert "Next action:" in output


def test_licence_check_command_returns_zero_for_active_licence(tmp_path, capsys):
    path = tmp_path / "licence.json"
    write_licence(path, create_trial_licence("buyer@example.com"))

    code = cli.licence_check_command(argparse.Namespace(licence=path))

    assert code == 0
    output = capsys.readouterr().out
    assert "Licence status: ACTIVE" in output
    assert "Days remaining:" in output
