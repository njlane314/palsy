from __future__ import annotations

from palsy.admission_output import format_admission_summary


def test_format_admission_summary_groups_findings_and_blockers():
    output = format_admission_summary(
        {
            "project": "demo",
            "environment": "ci",
            "lockfile_name": "requirements.txt",
            "lockfile_digest": "a" * 64,
            "dependency_count": 3,
            "decision": "deny",
            "reasons": ["1 dependency artefact denied", "1 dependency artefact requires review"],
            "policy_name": "test",
            "policy_hash": "b" * 64,
            "items": [
                {
                    "coordinate": {"ecosystem": "pypi", "name": "clean", "version": "1.0.0"},
                    "decision": "allow",
                    "reasons": ["all configured checks passed"],
                },
                {
                    "coordinate": {"ecosystem": "pypi", "name": "blocked", "version": "2.0.0"},
                    "decision": "deny",
                    "reasons": [
                        "static scan maximum severity high exceeds medium",
                        "artefact references network behaviour",
                    ],
                },
                {
                    "coordinate": {"ecosystem": "pypi", "name": "reviewed", "version": "3.0.0"},
                    "decision": "review",
                    "reasons": ["artefact references network behaviour"],
                },
            ],
            "permit": None,
        }
    )

    assert "Decision: DENY" in output
    assert "- 1 allowed" in output
    assert "- 1 needs review" in output
    assert "- 1 denied" in output
    assert "- 2 dependencies: artefact references network behaviour" in output
    assert "Denied dependencies (showing 1 of 1):" in output
    assert "Review dependencies (showing 1 of 1):" in output
