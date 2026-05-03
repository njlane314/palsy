from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .models import ArtifactStatus, Decision, Permit, ResolvedArtifact, ReviewApproval, ScanReport

SCHEMA = """
CREATE TABLE IF NOT EXISTS artifacts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ecosystem TEXT NOT NULL,
  project TEXT NOT NULL,
  version TEXT NOT NULL,
  filename TEXT NOT NULL,
  digest TEXT NOT NULL UNIQUE,
  url TEXT,
  size INTEGER,
  upload_time TEXT,
  media_type TEXT,
  published_at TEXT,
  resolved_json TEXT,
  status TEXT NOT NULL,
  storage_path TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_artifacts_project_version ON artifacts(project, version);
CREATE INDEX IF NOT EXISTS idx_artifacts_status ON artifacts(status);

CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  artifact_digest TEXT NOT NULL,
  report_json TEXT NOT NULL,
  max_severity TEXT NOT NULL,
  finding_count INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(artifact_digest) REFERENCES artifacts(digest)
);
CREATE INDEX IF NOT EXISTS idx_scans_digest ON scans(artifact_digest);

CREATE TABLE IF NOT EXISTS permits (
  id TEXT PRIMARY KEY,
  artifact_digest TEXT NOT NULL,
  environment TEXT NOT NULL,
  decision TEXT NOT NULL,
  policy_name TEXT NOT NULL,
  policy_hash TEXT NOT NULL,
  permit_json TEXT NOT NULL,
  signature TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  FOREIGN KEY(artifact_digest) REFERENCES artifacts(digest)
);
CREATE INDEX IF NOT EXISTS idx_permits_digest ON permits(artifact_digest);
CREATE INDEX IF NOT EXISTS idx_permits_environment ON permits(environment);

CREATE TABLE IF NOT EXISTS revocations (
  digest TEXT PRIMARY KEY,
  reason TEXT NOT NULL,
  actor TEXT NOT NULL,
  revoked_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS decisions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  artifact_digest TEXT NOT NULL,
  environment TEXT NOT NULL,
  decision TEXT NOT NULL,
  policy_name TEXT NOT NULL,
  policy_hash TEXT NOT NULL,
  reasons_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_decisions_digest ON decisions(artifact_digest);

CREATE TABLE IF NOT EXISTS review_approvals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  artifact_digest TEXT NOT NULL,
  environment TEXT NOT NULL,
  reviewer TEXT NOT NULL,
  reason TEXT NOT NULL,
  policy_name TEXT NOT NULL,
  policy_hash TEXT NOT NULL,
  approved_at TEXT NOT NULL,
  FOREIGN KEY(artifact_digest) REFERENCES artifacts(digest)
);
CREATE INDEX IF NOT EXISTS idx_review_approvals_digest ON review_approvals(artifact_digest);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Database:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.init()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.path), timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        try:
            yield conn
        finally:
            conn.close()

    def init(self) -> None:
        with self.connect() as conn:
            conn.executescript(SCHEMA)
            self._ensure_column(conn, "artifacts", "media_type", "TEXT")
            self._ensure_column(conn, "artifacts", "published_at", "TEXT")
            self._ensure_column(conn, "artifacts", "resolved_json", "TEXT")

    def _ensure_column(self, conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
        columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        if column not in columns:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def upsert_artifact(
        self,
        *,
        ecosystem: str,
        project: str,
        version: str,
        filename: str,
        digest: str,
        url: str | None,
        size: int | None,
        upload_time: str | None,
        status: ArtifactStatus,
        storage_path: str | None,
    ) -> None:
        timestamp = now_iso()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO artifacts(ecosystem, project, version, filename, digest, url, size, upload_time,
                                      status, storage_path, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(digest) DO UPDATE SET
                  project=excluded.project,
                  version=excluded.version,
                  filename=excluded.filename,
                  url=excluded.url,
                  size=excluded.size,
                  upload_time=excluded.upload_time,
                  status=excluded.status,
                  storage_path=excluded.storage_path,
                  updated_at=excluded.updated_at
                """,
                (
                    ecosystem,
                    project,
                    version,
                    filename,
                    digest,
                    url,
                    size,
                    upload_time,
                    status.value,
                    storage_path,
                    timestamp,
                    timestamp,
                ),
            )

    def upsert_resolved_artifact(
        self,
        *,
        digest: str,
        resolved: ResolvedArtifact,
        status: ArtifactStatus,
        storage_path: str | None,
        size: int | None = None,
    ) -> None:
        timestamp = now_iso()
        coordinate = resolved.coordinate
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO artifacts(ecosystem, project, version, filename, digest, url, size, upload_time,
                                      media_type, published_at, resolved_json, status, storage_path,
                                      created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(digest) DO UPDATE SET
                  ecosystem=excluded.ecosystem,
                  project=excluded.project,
                  version=excluded.version,
                  filename=excluded.filename,
                  url=excluded.url,
                  size=excluded.size,
                  upload_time=excluded.upload_time,
                  media_type=excluded.media_type,
                  published_at=excluded.published_at,
                  resolved_json=excluded.resolved_json,
                  status=excluded.status,
                  storage_path=excluded.storage_path,
                  updated_at=excluded.updated_at
                """,
                (
                    coordinate.ecosystem.value,
                    coordinate.name or coordinate.project or "unnamed",
                    coordinate.version,
                    resolved.filename,
                    digest,
                    resolved.url,
                    size or resolved.size,
                    resolved.published_at.isoformat() if resolved.published_at else None,
                    resolved.media_type,
                    resolved.published_at.isoformat() if resolved.published_at else None,
                    resolved.model_dump_json(),
                    status.value,
                    storage_path,
                    timestamp,
                    timestamp,
                ),
            )

    def set_artifact_status(self, digest: str, status: ArtifactStatus) -> None:
        with self.connect() as conn:
            conn.execute(
                "UPDATE artifacts SET status=?, updated_at=? WHERE digest=?",
                (status.value, now_iso(), digest),
            )

    def get_artifact(self, digest: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM artifacts WHERE digest=?", (digest,)).fetchone()
            return dict(row) if row else None

    def latest_scan(self, digest: str) -> ScanReport | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT report_json FROM scans WHERE artifact_digest=? ORDER BY id DESC LIMIT 1", (digest,)
            ).fetchone()
            if not row:
                return None
            return ScanReport.model_validate_json(row["report_json"])

    def save_scan(self, report: ScanReport) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO scans(artifact_digest, report_json, max_severity, finding_count, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    report.artifact_digest,
                    report.model_dump_json(),
                    report.max_severity.value,
                    len(report.findings),
                    now_iso(),
                ),
            )

    def save_decision(
        self,
        *,
        artifact_digest: str,
        environment: str,
        decision: Decision,
        policy_name: str,
        policy_hash: str,
        reasons: list[str],
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO decisions(artifact_digest, environment, decision, policy_name, policy_hash, reasons_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    artifact_digest,
                    environment,
                    decision.value,
                    policy_name,
                    policy_hash,
                    json.dumps(reasons, sort_keys=True),
                    now_iso(),
                ),
            )

    def save_permit(self, permit: Permit) -> None:
        if not permit.signature:
            raise ValueError("permit must be signed before persistence")
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO permits(id, artifact_digest, environment, decision, policy_name, policy_hash,
                                    permit_json, signature, expires_at, revoked, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                  permit_json=excluded.permit_json,
                  signature=excluded.signature,
                  expires_at=excluded.expires_at,
                  revoked=excluded.revoked
                """,
                (
                    permit.id,
                    permit.subject.digest,
                    permit.environment.value,
                    permit.decision.value,
                    permit.policy_name,
                    permit.policy_hash,
                    permit.model_dump_json(),
                    permit.signature,
                    permit.expires_at.isoformat(),
                    1 if permit.revoked else 0,
                    now_iso(),
                ),
            )

    def get_permit(self, permit_id: str) -> Permit | None:
        with self.connect() as conn:
            row = conn.execute("SELECT permit_json FROM permits WHERE id=?", (permit_id,)).fetchone()
            if not row:
                return None
            return Permit.model_validate_json(row["permit_json"])

    def latest_valid_permit(self, digest: str, environment: str | None = None) -> Permit | None:
        query = "SELECT permit_json FROM permits WHERE artifact_digest=? AND revoked=0"
        params: list[Any] = [digest]
        if environment:
            query += " AND environment=?"
            params.append(environment)
        query += " ORDER BY created_at DESC LIMIT 1"
        with self.connect() as conn:
            row = conn.execute(query, params).fetchone()
            if not row:
                return None
            return Permit.model_validate_json(row["permit_json"])

    def revoke(self, digest: str, reason: str, actor: str) -> None:
        with self.connect() as conn:
            timestamp = now_iso()
            conn.execute(
                """
                INSERT INTO revocations(digest, reason, actor, revoked_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(digest) DO UPDATE SET reason=excluded.reason, actor=excluded.actor, revoked_at=excluded.revoked_at
                """,
                (digest, reason, actor, timestamp),
            )
            conn.execute("UPDATE permits SET revoked=1 WHERE artifact_digest=?", (digest,))
            conn.execute("UPDATE artifacts SET status=?, updated_at=? WHERE digest=?", (ArtifactStatus.revoked.value, timestamp, digest))

    def is_revoked(self, digest: str) -> bool:
        with self.connect() as conn:
            row = conn.execute("SELECT 1 FROM revocations WHERE digest=?", (digest,)).fetchone()
            return bool(row)

    def artifacts_for_project(self, project: str, status: ArtifactStatus | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM artifacts WHERE project=?"
        params: list[Any] = [project]
        if status is not None:
            query += " AND status=?"
            params.append(status.value)
        query += " ORDER BY created_at DESC"
        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(row) for row in rows]

    def artifacts_for_package(
        self,
        ecosystem: str,
        project: str,
        status: ArtifactStatus | None = None,
    ) -> list[dict[str, Any]]:
        query = "SELECT * FROM artifacts WHERE ecosystem=? AND project=?"
        params: list[Any] = [ecosystem, project]
        if status is not None:
            query += " AND status=?"
            params.append(status.value)
        query += " ORDER BY created_at DESC"
        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(row) for row in rows]

    def review_artifacts(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM artifacts
                WHERE status=?
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                (ArtifactStatus.review.value, limit),
            ).fetchall()
            return [dict(row) for row in rows]

    def latest_decision(self, digest: str, environment: str | None = None) -> dict[str, Any] | None:
        query = "SELECT * FROM decisions WHERE artifact_digest=?"
        params: list[Any] = [digest]
        if environment:
            query += " AND environment=?"
            params.append(environment)
        query += " ORDER BY id DESC LIMIT 1"
        with self.connect() as conn:
            row = conn.execute(query, params).fetchone()
            return dict(row) if row else None

    def save_review_approval(self, approval: ReviewApproval) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO review_approvals(artifact_digest, environment, reviewer, reason,
                                             policy_name, policy_hash, approved_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    approval.digest,
                    approval.environment.value,
                    approval.reviewer,
                    approval.reason,
                    approval.policy_name,
                    approval.policy_hash,
                    approval.approved_at.isoformat(),
                ),
            )

    def allowed_files_for_project(self, project: str) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT project, version, filename, digest, storage_path, size
                FROM artifacts
                WHERE project=? AND status=?
                ORDER BY version, filename
                """,
                (project, ArtifactStatus.allowed.value),
            ).fetchall()
            return [dict(row) for row in rows]

    def allowed_files_for_ecosystem_project(self, ecosystem: str, project: str) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM artifacts
                WHERE ecosystem=? AND project=? AND status=?
                ORDER BY version, filename
                """,
                (ecosystem, project, ArtifactStatus.allowed.value),
            ).fetchall()
            return [dict(row) for row in rows]

    def affected_by_digest(self, digest: str) -> dict[str, Any]:
        # Minimal local blast-radius view. In a full deployment this table would be extended
        # with lockfile/build/image/deployment edges.
        with self.connect() as conn:
            artifact = conn.execute("SELECT * FROM artifacts WHERE digest=?", (digest,)).fetchone()
            permits = conn.execute("SELECT * FROM permits WHERE artifact_digest=?", (digest,)).fetchall()
            decisions = conn.execute("SELECT * FROM decisions WHERE artifact_digest=?", (digest,)).fetchall()
            approvals = conn.execute(
                "SELECT * FROM review_approvals WHERE artifact_digest=? ORDER BY approved_at DESC",
                (digest,),
            ).fetchall()
            return {
                "artifact": dict(artifact) if artifact else None,
                "permits": [dict(row) for row in permits],
                "decisions": [dict(row) for row in decisions],
                "review_approvals": [dict(row) for row in approvals],
            }
