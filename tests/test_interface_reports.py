from __future__ import annotations

from pathlib import Path

from palsy.admission_report import build_admission_document, load_admission_document, write_admission_document
from palsy.policy_composer import policy_explanation, policy_from_preset
from palsy.report_html import render_dependency_passport
from palsy.report_markdown import render_markdown_summary


def test_admission_document_adds_diff_explanations_and_autopsy(tmp_path: Path):
    baseline = build_admission_document(_result(items=[_item("pypi", "idna", "3.10", "allow")]))
    document = build_admission_document(
        _result(
            decision="deny",
            items=[
                _item("pypi", "idna", "3.10", "allow"),
                _item(
                    "pypi",
                    "suspicious-wheel",
                    "0.2.1",
                    "deny",
                    reasons=["executable .pth startup hook is not allowlisted"],
                    capabilities={"has_pth_exec": True},
                ),
            ],
        ),
        baseline=baseline,
    )

    assert document["schema"] == "palsy.admission.v1"
    assert document["diff"]["summary"]["added"] == 1
    assert document["counts"]["deny"] == 1
    assert any(e["title"] == "Executable Python startup hook" for e in document["explanations"])
    assert document["autopsies"][1]["risk_signals"] == ["has_pth_exec"]

    out = tmp_path / "admission.json"
    write_admission_document(out, document)
    assert load_admission_document(out)["schema"] == "palsy.admission.v1"


def test_html_and_markdown_renderers_include_product_surfaces():
    document = build_admission_document(
        _result(
            decision="review",
            items=[
                _item(
                    "npm",
                    "left-pad-plus",
                    "1.4.0",
                    "review",
                    reasons=["npm install/lifecycle script is not allowlisted"],
                    capabilities={"has_lifecycle_scripts": True},
                )
            ],
        )
    )

    html = render_dependency_passport(document)
    markdown = render_markdown_summary(document)

    assert "Palsy Passport" in html
    assert "Dependency Diff" in html
    assert "Explain This Decision" in html
    assert "Artefact Autopsy" in html
    assert "Palsy Dependency Admission" in markdown


def test_policy_composer_preset_explains_policy():
    policy = policy_from_preset("ci-balanced", environment="ci")
    explanation = policy_explanation(policy)

    assert policy["mode"] == "enforce"
    assert "no permit, no build" in explanation.lower()


def _result(decision: str = "allow", items: list[dict] | None = None) -> dict:
    return {
        "project": "demo",
        "environment": "ci",
        "lockfile_name": "requirements.txt",
        "lockfile_digest": "a" * 64,
        "dependency_count": len(items or []),
        "decision": decision,
        "reasons": ["all configured checks passed"] if decision == "allow" else ["dependency artefact denied"],
        "policy_name": "test-policy",
        "policy_hash": "b" * 64,
        "items": items or [],
        "permit": {"id": "permit-1"} if decision == "allow" else None,
    }


def _item(
    ecosystem: str,
    name: str,
    version: str,
    decision: str,
    *,
    reasons: list[str] | None = None,
    capabilities: dict | None = None,
) -> dict:
    return {
        "coordinate": {"ecosystem": ecosystem, "name": name, "project": name, "version": version},
        "digest": "c" * 64,
        "filename": f"{name}-{version}.tgz",
        "decision": decision,
        "reasons": reasons or ["all configured checks passed"],
        "permit_id": "permit-dep" if decision == "allow" else None,
        "max_severity": "info" if decision == "allow" else "high",
        "finding_count": 0 if decision == "allow" else 1,
        "capabilities": capabilities or {},
        "findings": [],
        "file_count": 12,
        "total_uncompressed_size": 3456,
        "top_level_modules": [name.replace("-", "_")],
    }
