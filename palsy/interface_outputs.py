from __future__ import annotations

from pathlib import Path
from typing import Any

from .admission_report import build_admission_document, load_admission_document, write_admission_document
from .report_html import render_dependency_passport
from .report_markdown import render_markdown_summary


def emit_report_bundle(
    result: dict[str, Any],
    *,
    report_dir: Path | None,
    out: Path | None = None,
    html: Path | None = None,
    summary: Path | None = None,
    baseline: Path | None = None,
    no_report: bool = False,
) -> dict[str, Path]:
    if no_report or report_dir is None:
        return {}
    report_dir.mkdir(parents=True, exist_ok=True)

    baseline_document = load_admission_document(baseline) if baseline else None
    document = build_admission_document(result, baseline=baseline_document)
    admission_path = out or report_dir / "admission.json"
    html_path = html or report_dir / "dependency-passport.html"
    summary_path = summary or report_dir / "summary.md"

    write_admission_document(admission_path, document)
    write_rendered_outputs(document, html_path, summary_path)
    return {"admission": admission_path, "html": html_path, "summary": summary_path}


def write_rendered_outputs(document: dict[str, Any], html_path: Path, summary_path: Path) -> None:
    html_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    html_path.write_text(render_dependency_passport(document), encoding="utf-8")
    summary_path.write_text(render_markdown_summary(document), encoding="utf-8")


def safe_lockfile_stem(lockfile_name: str) -> str:
    return lockfile_name.replace("/", "_").replace("\\", "_")
