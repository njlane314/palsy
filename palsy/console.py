from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .admission_report import load_admission_document


RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
BLUE = "\033[34m"


def run_console(path: Path) -> int:
    document = load_admission_document(path)
    selected = 0
    while True:
        _clear()
        _render(document, selected)
        command = input("\n[d]own [u]p [e]xplain [a]utopsy [q]uit > ").strip().lower()
        items = document.get("items") or []
        if command in {"q", "quit", "exit"}:
            return 0
        if command in {"d", "down", "j"} and items:
            selected = min(selected + 1, len(items) - 1)
        elif command in {"u", "up", "k"} and items:
            selected = max(selected - 1, 0)
        elif command in {"e", "explain"}:
            _pause(_explain(items[selected] if items else None))
        elif command in {"a", "autopsy"}:
            autopsies = document.get("autopsies") or []
            autopsy = next((a for a in autopsies if items and a.get("key") == items[selected].get("key")), None)
            _pause(_autopsy(autopsy))


def _render(document: dict[str, Any], selected: int) -> None:
    decision = str(document.get("decision") or "unknown")
    counts = document.get("counts") or {}
    diff = document.get("diff") or {"summary": {}}
    print(f"{BOLD}Palsy Console{RESET}  {DIM}policy={document.get('policy_name')} env={document.get('environment')}{RESET}")
    print("-" * 92)
    print(f"Admission: {_badge(decision)}  lockfile={document.get('lockfile_name')}  project={document.get('project')}")
    print(
        f"Counts: {GREEN}{counts.get('allow', 0)} allow{RESET}  "
        f"{YELLOW}{counts.get('review', 0)} review{RESET}  "
        f"{RED}{counts.get('deny', 0)} deny{RESET}"
    )
    summary = diff.get("summary") or {}
    print(
        f"Diff: +{summary.get('added', 0)} added  -{summary.get('removed', 0)} removed  "
        f"~{summary.get('changed', 0)} changed  signals={summary.get('new_signals', 0)}"
    )
    print("-" * 92)
    print(f"{BOLD}Dependency Diff / Inventory{RESET}")
    items = document.get("items") or []
    for idx, item in enumerate(items[:40]):
        marker = ">" if idx == selected else " "
        print(f"{marker} {_badge(str(item.get('decision'))):18} {item.get('key'):<46.46} {DIM}{str(item.get('severity') or ''):<8}{RESET}")
    if len(items) > 40:
        print(f"{DIM}... {len(items) - 40} more dependencies omitted in console view{RESET}")
    print("-" * 92)
    if items:
        current = items[selected]
        print(f"{BOLD}Explain This Decision{RESET}: {current.get('key')}")
        for reason in (current.get("reasons") or ["all configured checks passed"]):
            print(f"  - {reason}")
        signals = ", ".join(current.get("signals") or []) or "none"
        print(f"{BOLD}Artefact Autopsy{RESET}: signals={signals} digest={current.get('digest') or 'unknown'}")
    print("-" * 92)


def _explain(item: dict[str, Any] | None) -> str:
    if not item:
        return "No dependency selected."
    lines = [f"Explain: {item.get('key')}", ""]
    for explanation in item.get("explanations") or []:
        lines.extend(
            [
                f"{explanation.get('title')} [{explanation.get('severity')}]",
                f"Reason: {explanation.get('reason')}",
                f"Why: {explanation.get('why')}",
                f"Fix: {explanation.get('fix')}",
                "",
            ]
        )
    return "\n".join(lines) if len(lines) > 2 else "No explanation available."


def _autopsy(autopsy: dict[str, Any] | None) -> str:
    if not autopsy:
        return "No autopsy available for this dependency."
    identity = autopsy.get("identity") or {}
    anatomy = autopsy.get("anatomy") or {}
    lines = [
        f"Artefact Autopsy: {autopsy.get('key')}",
        "",
        f"Decision: {autopsy.get('decision')}",
        f"Filename: {identity.get('filename')}",
        f"Digest: {identity.get('digest')}",
        f"URL: {identity.get('url')}",
        f"Files: {anatomy.get('file_count')}",
        f"Uncompressed bytes: {anatomy.get('total_uncompressed_size')}",
        f"Top-level modules: {', '.join(anatomy.get('top_level_modules') or []) or 'unknown'}",
        f"Risk signals: {', '.join(autopsy.get('risk_signals') or []) or 'none'}",
        "",
        "Reasons:",
    ]
    lines.extend(f"- {reason}" for reason in autopsy.get("reasons") or [])
    return "\n".join(lines)


def _badge(decision: str) -> str:
    color = {"allow": GREEN, "review": YELLOW, "deny": RED}.get(decision, BLUE)
    return f"{color}{decision.upper():<8}{RESET}"


def _clear() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def _pause(text: str) -> None:
    _clear()
    print(text)
    input("\nPress enter to return to Palsy Console...")
