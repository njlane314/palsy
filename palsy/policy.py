from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

from .models import Decision, Environment, PolicyDecision, SandboxReport, ScanReport, Severity, SEVERITY_RANK, PyPIFile


class PolicyConfig(BaseModel):
    name: str = "pypi-default"
    mode: Literal["observe", "warn", "enforce"] = "enforce"
    minimum_release_age_seconds: dict[str, int] = Field(default_factory=lambda: {"default": 86400})
    allow_pth_exec: list[str] = Field(default_factory=list)
    allow_native_code: list[str] = Field(default_factory=list)
    allow_import_network: list[str] = Field(default_factory=list)
    allow_hidden_runtime: list[str] = Field(default_factory=list)
    trusted_publishers: dict[str, str] = Field(default_factory=dict)
    max_allowed_severity: Severity = Severity.medium
    review_on_severity: Severity = Severity.high
    permit_ttl_seconds: int = 604800
    require_sandbox_for_prod: bool = True

    @classmethod
    def load(cls, path: Path | None) -> "PolicyConfig":
        if path is None or not path.exists():
            return cls()
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return cls.model_validate(data)

    @property
    def hash(self) -> str:
        payload = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class PolicyContext:
    project: str
    version: str
    environment: Environment
    file: PyPIFile
    scan: ScanReport
    sandbox: SandboxReport | None = None
    previous_scan: ScanReport | None = None
    revoked: bool = False


@dataclass
class PolicyEngine:
    config: PolicyConfig = field(default_factory=PolicyConfig)

    def evaluate(self, ctx: PolicyContext) -> PolicyDecision:
        deny: list[str] = []
        review: list[str] = []
        project = ctx.project.lower().replace("_", "-")

        if ctx.revoked:
            deny.append("artefact digest has been revoked")

        if ctx.file.yanked:
            deny.append("upstream file is yanked")

        age_reason = self._release_age_reason(ctx)
        if age_reason:
            if ctx.environment == Environment.prod:
                deny.append(age_reason)
            else:
                review.append(age_reason)

        max_sev = ctx.scan.max_severity
        if SEVERITY_RANK[max_sev] > SEVERITY_RANK[self.config.max_allowed_severity]:
            deny.append(f"static scan maximum severity {max_sev.value} exceeds {self.config.max_allowed_severity.value}")
        elif SEVERITY_RANK[max_sev] >= SEVERITY_RANK[self.config.review_on_severity]:
            review.append(f"static scan maximum severity is {max_sev.value}")

        caps = ctx.scan.capabilities
        if caps.has_pth_exec and project not in self._norm_list(self.config.allow_pth_exec):
            deny.append("executable .pth startup hook is not allowlisted")
        if caps.has_hidden_runtime and project not in self._norm_list(self.config.allow_hidden_runtime):
            deny.append("hidden/runtime staging directory is not allowlisted")
        if caps.has_native_code and project not in self._norm_list(self.config.allow_native_code):
            if ctx.environment == Environment.prod:
                review.append("native code present and package is not native-code allowlisted")
            else:
                review.append("native code present")
        if caps.import_time_sensitive:
            review.append("package has sensitive import-time behaviour")
        if caps.references_network and project not in self._norm_list(self.config.allow_import_network):
            review.append("artefact references network behaviour")

        if ctx.previous_scan:
            self._evaluate_diff(ctx.scan, ctx.previous_scan, ctx.environment, deny, review)

        if ctx.environment == Environment.prod and self.config.require_sandbox_for_prod:
            if not ctx.sandbox or not ctx.sandbox.enabled or not ctx.sandbox.executed:
                deny.append("production policy requires sandbox execution")

        if ctx.sandbox and ctx.sandbox.enabled:
            high_events = [e for e in ctx.sandbox.events if SEVERITY_RANK[e.severity] >= SEVERITY_RANK[Severity.high]]
            med_events = [e for e in ctx.sandbox.events if e.severity == Severity.medium]
            if any(e.kind in {"env.read", "network.connect", "process.spawn"} for e in high_events):
                deny.append("sandbox observed credential read, network connect, or process spawn")
            elif high_events:
                review.append("sandbox produced high-severity events")
            elif med_events:
                review.append("sandbox produced medium-severity events")

        decision = Decision.allow
        reasons: list[str] = []
        if deny:
            decision = Decision.deny
            reasons = deny + review
        elif review:
            decision = Decision.review
            reasons = review

        if self.config.mode == "observe" and decision != Decision.allow:
            reasons = [f"observe-only: would {decision.value}: {r}" for r in reasons]
            decision = Decision.allow
        elif self.config.mode == "warn" and decision == Decision.review:
            reasons = [f"warn-only: {r}" for r in reasons]
            decision = Decision.allow

        return PolicyDecision(
            decision=decision,
            reasons=reasons or ["all configured checks passed"],
            policy_name=self.config.name,
            policy_hash=self.config.hash,
        )

    def _release_age_reason(self, ctx: PolicyContext) -> str | None:
        uploaded = ctx.file.upload_time_iso_8601
        if not uploaded:
            return "upstream upload timestamp is unavailable"
        if uploaded.tzinfo is None:
            uploaded = uploaded.replace(tzinfo=timezone.utc)
        minimum = self.config.minimum_release_age_seconds.get(
            ctx.environment.value,
            self.config.minimum_release_age_seconds.get("default", 0),
        )
        age_seconds = (datetime.now(timezone.utc) - uploaded.astimezone(timezone.utc)).total_seconds()
        if age_seconds < minimum:
            return f"release age {int(age_seconds)}s is below {minimum}s threshold for {ctx.environment.value}"
        return None

    def _evaluate_diff(
        self,
        scan: ScanReport,
        previous: ScanReport,
        environment: Environment,
        deny: list[str],
        review: list[str],
    ) -> None:
        curr = scan.capabilities
        prev = previous.capabilities
        if curr.has_pth_exec and not prev.has_pth_exec:
            deny.append("new version introduced executable .pth startup hook")
        if curr.has_hidden_runtime and not prev.has_hidden_runtime:
            deny.append("new version introduced hidden/runtime staging directory")
        if curr.has_embedded_interpreter and not prev.has_embedded_interpreter:
            deny.append("new version introduced embedded interpreter/runtime")
        if curr.has_native_code and not prev.has_native_code:
            if environment == Environment.prod:
                deny.append("new version introduced native code in production candidate")
            else:
                review.append("new version introduced native code")
        if curr.import_time_sensitive and not prev.import_time_sensitive:
            review.append("new version introduced sensitive import-time behaviour")

        prev_deps = set(previous.metadata.get("requires_dist", []))
        curr_deps = set(scan.metadata.get("requires_dist", []))
        added = curr_deps - prev_deps
        if len(added) >= 10:
            review.append(f"new version added {len(added)} dependency declarations")

    def _norm_list(self, values: list[str]) -> set[str]:
        return {value.lower().replace("_", "-") for value in values}
