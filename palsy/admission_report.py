from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .explain import explain_reasons


SCHEMA = "palsy.admission.v1"
DECISION_RANK = {"allow": 0, "review": 1, "deny": 2}


def build_admission_document(
    result: dict[str, Any],
    *,
    baseline: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if result.get("schema") == SCHEMA:
        current = dict(result)
    else:
        current = _normalise_result(result)

    baseline_doc = _coerce_document(baseline) if baseline else None
    baseline_items = baseline_doc.get("items", []) if baseline_doc else []
    current["diff"] = _build_diff(current.get("items", []), baseline_items)
    current["explanations"] = _build_explanations(current.get("items", []), current.get("reasons", []))
    current["autopsies"] = [_build_autopsy(item) for item in current.get("items", [])]
    current["signals"] = _signal_counts(current.get("items", []))
    return current


def load_admission_document(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("admission document must be a JSON object")
    return _coerce_document(data)


def write_admission_document(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


def _coerce_document(data: dict[str, Any] | None) -> dict[str, Any]:
    if not data:
        return build_admission_document({})
    if data.get("schema") == SCHEMA:
        return data
    return build_admission_document(data)


def _normalise_result(result: dict[str, Any]) -> dict[str, Any]:
    items = [_normalise_item(item) for item in list(result.get("items") or [])]
    counts = Counter(item["decision"] for item in items)
    permit = result.get("permit") or None
    decision = str(result.get("decision") or _worst_decision(items) or "unknown")
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project": result.get("project"),
        "environment": result.get("environment"),
        "lockfile_name": result.get("lockfile_name"),
        "lockfile_digest": result.get("lockfile_digest"),
        "dependency_count": int(result.get("dependency_count") or len(items)),
        "decision": decision,
        "decision_label": decision.upper(),
        "status": _status_sentence(decision),
        "reasons": list(result.get("reasons") or []),
        "policy_name": result.get("policy_name"),
        "policy_hash": result.get("policy_hash"),
        "counts": {
            "allow": counts.get("allow", 0),
            "review": counts.get("review", 0),
            "deny": counts.get("deny", 0),
        },
        "items": items,
        "permit": permit,
        "raw": result,
    }


def _normalise_item(item: dict[str, Any]) -> dict[str, Any]:
    coordinate = dict(item.get("coordinate") or {})
    ecosystem = str(coordinate.get("ecosystem") or "unknown")
    name = str(coordinate.get("name") or coordinate.get("project") or "unknown")
    version = str(coordinate.get("version") or "unversioned")
    decision = str(item.get("decision") or "unknown")
    reasons = list(item.get("reasons") or [])
    capabilities = item.get("capabilities") or {}
    findings = list(item.get("findings") or [])
    return {
        "key": f"{ecosystem}:{name}@{version}",
        "ecosystem": ecosystem,
        "name": name,
        "version": version,
        "coordinate": coordinate,
        "decision": decision,
        "decision_label": decision.upper(),
        "severity": str(item.get("max_severity") or _severity_from_reasons(reasons)),
        "digest": item.get("digest"),
        "filename": item.get("filename"),
        "permit_id": item.get("permit_id"),
        "finding_count": int(item.get("finding_count") or len(findings)),
        "reasons": reasons,
        "explanations": explain_reasons(reasons),
        "capabilities": capabilities,
        "findings": findings,
        "top_level_modules": list(item.get("top_level_modules") or []),
        "file_count": int(item.get("file_count") or 0),
        "total_uncompressed_size": int(item.get("total_uncompressed_size") or 0),
        "metadata": item.get("metadata") or {},
        "resolved_url": item.get("resolved_url"),
        "media_type": item.get("media_type"),
        "published_at": item.get("published_at"),
        "mutable_reference": bool(item.get("mutable_reference") or False),
        "signals": _signals_for_item(reasons, capabilities),
    }


def _build_diff(items: list[dict[str, Any]], baseline_items: list[dict[str, Any]]) -> dict[str, Any]:
    before = {item.get("key"): item for item in baseline_items if item.get("key")}
    after = {item.get("key"): item for item in items if item.get("key")}
    added = [after[key] for key in sorted(after.keys() - before.keys())]
    removed = [before[key] for key in sorted(before.keys() - after.keys())]
    changed: list[dict[str, Any]] = []
    for key in sorted(before.keys() & after.keys()):
        old = before[key]
        new = after[key]
        if old.get("decision") != new.get("decision") or old.get("digest") != new.get("digest"):
            changed.append({"key": key, "before": old, "after": new})
    new_signals = sorted({signal for item in added + items for signal in item.get("signals", [])})
    return {
        "has_baseline": bool(baseline_items),
        "added": added,
        "removed": removed,
        "changed": changed,
        "new_signals": new_signals,
        "summary": {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
            "new_signals": len(new_signals),
        },
    }


def _build_explanations(items: list[dict[str, Any]], graph_reasons: list[str]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    explanations: list[dict[str, Any]] = []
    for explanation in explain_reasons(graph_reasons):
        key = str(explanation.get("reason"))
        if key not in seen:
            explanations.append(explanation)
            seen.add(key)
    for item in items:
        if item.get("decision") == "allow":
            continue
        for explanation in item.get("explanations", []):
            key = str(explanation.get("reason"))
            if key in seen:
                continue
            enriched = dict(explanation)
            enriched["artefact"] = item.get("key")
            explanations.append(enriched)
            seen.add(key)
    return explanations


def _build_autopsy(item: dict[str, Any]) -> dict[str, Any]:
    capabilities = item.get("capabilities") or {}
    true_capabilities = sorted(name for name, value in capabilities.items() if value is True)
    return {
        "key": item.get("key"),
        "identity": {
            "ecosystem": item.get("ecosystem"),
            "name": item.get("name"),
            "version": item.get("version"),
            "filename": item.get("filename"),
            "digest": item.get("digest"),
            "url": item.get("resolved_url"),
            "media_type": item.get("media_type"),
            "published_at": item.get("published_at"),
        },
        "anatomy": {
            "file_count": item.get("file_count"),
            "total_uncompressed_size": item.get("total_uncompressed_size"),
            "top_level_modules": item.get("top_level_modules") or [],
        },
        "risk_signals": true_capabilities or item.get("signals", []),
        "findings": item.get("findings") or [],
        "decision": item.get("decision"),
        "reasons": item.get("reasons") or [],
    }


def _signal_counts(items: list[dict[str, Any]]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for item in items:
        counts.update(item.get("signals", []))
    return dict(sorted(counts.items()))


def _signals_for_item(reasons: list[str], capabilities: dict[str, Any]) -> list[str]:
    signals: set[str] = set()
    reason_text = " ".join(reasons).lower()
    mapping = {
        "pth": "python_startup_hook",
        "startup hook": "python_startup_hook",
        "lifecycle": "npm_lifecycle_script",
        "native code": "native_code",
        "network": "network_reference",
        "mutable tag": "mutable_oci_reference",
        "embedded": "embedded_runtime",
        "hidden/runtime": "hidden_runtime",
        "release age": "fresh_release",
        "expected digest": "missing_expected_digest",
    }
    for fragment, signal in mapping.items():
        if fragment in reason_text:
            signals.add(signal)
    for name, value in capabilities.items():
        if value is True:
            signals.add(name)
    return sorted(signals)


def _worst_decision(items: list[dict[str, Any]]) -> str | None:
    if not items:
        return None
    return max((item.get("decision", "allow") for item in items), key=lambda value: DECISION_RANK.get(value, -1))


def _severity_from_reasons(reasons: list[str]) -> str:
    text = " ".join(reasons).lower()
    if any(token in text for token in ("deny", "exceeds", "pth", "embedded", "mutable tag")):
        return "high"
    if any(token in text for token in ("review", "native", "network", "release age", "lifecycle")):
        return "medium"
    return "info"


def _status_sentence(decision: str) -> str:
    if decision == "allow":
        return "admitted: a signed build permit may be archived with this build."
    if decision == "review":
        return "held for review: at least one artefact needs human approval before the build is admitted."
    if decision == "deny":
        return "blocked: the dependency graph is not admitted under the active policy."
    return "unknown: inspect the raw admission response."
