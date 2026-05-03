from __future__ import annotations

from typing import Any


def render_markdown_summary(document: dict[str, Any]) -> str:
    counts = document.get("counts") or {}
    permit = document.get("permit") or {}
    diff = document.get("diff") or {"summary": {}}
    summary = diff.get("summary") or {}
    lines = [
        "# Palsy Dependency Admission",
        "",
        f"**Decision:** {str(document.get('decision', 'unknown')).upper()}",
        f"**Project:** {document.get('project')}",
        f"**Environment:** {document.get('environment')}",
        f"**Lockfile:** {document.get('lockfile_name')}",
        f"**Policy:** {document.get('policy_name')} `{str(document.get('policy_hash') or '')[:12]}`",
        "",
        "## Result",
        "",
        str(document.get("status") or ""),
        "",
        "## Counts",
        "",
        f"- Allowed: {counts.get('allow', 0)}",
        f"- Review: {counts.get('review', 0)}",
        f"- Denied: {counts.get('deny', 0)}",
        "",
        "## Dependency Diff",
        "",
        f"- Added: {summary.get('added', 0)}",
        f"- Removed: {summary.get('removed', 0)}",
        f"- Changed: {summary.get('changed', 0)}",
        f"- New signals: {summary.get('new_signals', 0)}",
    ]
    if permit:
        lines.extend(["", "## Build Permit", "", f"`{permit.get('id')}`"])
    blockers = [item for item in document.get("items", []) if item.get("decision") in {"review", "deny"}]
    if blockers:
        lines.extend(["", "## Review Or Denied Artefacts", ""])
        for item in blockers[:20]:
            reasons = "; ".join(item.get("reasons") or [])
            lines.append(f"- **{item.get('decision', '').upper()}** `{item.get('key')}` - {reasons}")
    return "\n".join(lines).rstrip() + "\n"
