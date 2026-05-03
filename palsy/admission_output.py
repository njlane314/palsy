from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from typing import Any


DECISION_ORDER = ("allow", "review", "deny")


def format_admission_summary(result: Mapping[str, Any], *, max_items: int = 10) -> str:
    items = list(result.get("items") or [])
    decision = str(result.get("decision", "unknown"))
    lines = [
        "Palsy lockfile admission",
        f"Decision: {decision.upper()}",
        f"Result: {_decision_sentence(decision)}",
        "",
        f"Project: {result.get('project')}",
        f"Environment: {result.get('environment')}",
        f"Lockfile: {result.get('lockfile_name')}",
        f"Lockfile digest: {result.get('lockfile_digest')}",
        f"Policy: {result.get('policy_name')} ({str(result.get('policy_hash', ''))[:12]})",
        "",
    ]
    lines.extend(_dependency_count_lines(result, items))
    lines.extend(_reason_lines(result))
    lines.extend(_finding_lines(items))
    lines.extend(_dependency_section("Denied dependencies", _items_with_decision(items, "deny"), max_items))
    lines.extend(_dependency_section("Review dependencies", _items_with_decision(items, "review"), max_items))

    permit = result.get("permit")
    if permit:
        lines.extend(["", f"Build permit: {permit.get('id')}"])
    lines.extend(["", f"Next action: {_next_action(decision)}"])
    return "\n".join(lines)


def _decision_sentence(decision: str) -> str:
    if decision == "allow":
        return "admitted. CI or deployment may continue with this exact lockfile."
    if decision == "review":
        return "held for review. The graph is not admitted until a reviewer accepts it."
    if decision == "deny":
        return "blocked. The graph is not admitted under the current policy."
    return "unknown. Inspect the raw JSON response."


def _dependency_count_lines(result: Mapping[str, Any], items: list[Mapping[str, Any]]) -> list[str]:
    counts = Counter(str(item.get("decision", "unknown")) for item in items)
    total = int(result.get("dependency_count") or len(items))
    lines = [f"Dependencies: {total} total"]
    for decision in DECISION_ORDER:
        count = counts.get(decision, 0)
        if count:
            lines.append(f"- {count} {_dependency_label(decision, count)}")
    unknown = sum(count for decision, count in counts.items() if decision not in DECISION_ORDER)
    if unknown:
        lines.append(f"- {unknown} unknown")
    return lines


def _dependency_label(decision: str, count: int) -> str:
    if decision == "allow":
        return "allowed" if count != 1 else "allowed"
    if decision == "review":
        return "need review" if count != 1 else "needs review"
    if decision == "deny":
        return "denied" if count != 1 else "denied"
    return decision


def _reason_lines(result: Mapping[str, Any]) -> list[str]:
    reasons = list(result.get("reasons") or [])
    if not reasons:
        return []
    lines = ["", "Graph decision reasons:"]
    lines.extend(f"- {reason}" for reason in reasons)
    return lines


def _finding_lines(items: list[Mapping[str, Any]], limit: int = 6) -> list[str]:
    counts = Counter(
        reason
        for item in items
        if item.get("decision") != "allow"
        for reason in item.get("reasons", [])
        if reason != "all configured checks passed"
    )
    if not counts:
        return []
    lines = ["", "Most common findings:"]
    for reason, count in counts.most_common(limit):
        label = "dependency" if count == 1 else "dependencies"
        lines.append(f"- {count} {label}: {reason}")
    return lines


def _items_with_decision(items: list[Mapping[str, Any]], decision: str) -> list[Mapping[str, Any]]:
    return [item for item in items if item.get("decision") == decision]


def _dependency_section(title: str, items: list[Mapping[str, Any]], max_items: int) -> list[str]:
    if not items:
        return []
    shown = items[:max_items]
    lines = ["", f"{title} (showing {len(shown)} of {len(items)}):"]
    for item in shown:
        lines.append(f"- {_coordinate_label(item.get('coordinate') or {})}")
        reason_text = _short_reasons(item.get("reasons") or [])
        if reason_text:
            lines.append(f"  {reason_text}")
    return lines


def _coordinate_label(coordinate: Mapping[str, Any]) -> str:
    name = coordinate.get("name") or coordinate.get("project") or "unknown"
    version = coordinate.get("version") or "unversioned"
    ecosystem = coordinate.get("ecosystem") or "unknown"
    return f"{ecosystem}:{name}@{version}"


def _short_reasons(reasons: list[str], limit: int = 3) -> str:
    selected = reasons[:limit]
    suffix = f" (+{len(reasons) - limit} more)" if len(reasons) > limit else ""
    return "; ".join(selected) + suffix


def _next_action(decision: str) -> str:
    if decision == "allow":
        return "proceed and archive the build permit with the build artefacts."
    if decision == "review":
        return "send the review dependencies to a reviewer before installing or building."
    if decision == "deny":
        return "block the build, then review denied dependencies or tune policy for known-safe packages."
    return "inspect the raw JSON response."
