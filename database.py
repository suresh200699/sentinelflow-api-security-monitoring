"""SQLite persistence layer for SentinelFlow.

All SQL values are parameterized; this module exposes dictionaries so the UI
and tests do not need to depend on sqlite connection details.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

from detection_engine import parse_utc_timestamp


DEFAULT_DB_PATH = Path(__file__).with_name("sentinelflow.db")
VALID_STATUSES = {"Open", "Investigating", "Resolved"}
VALID_SEVERITIES = {"Low", "Medium", "High", "Critical"}
VALID_CLASSIFICATIONS = {"Normal", "Suspicious"}
MAX_TEXT_LENGTH = 500
MAX_EVIDENCE_LENGTH = 8_000


class DatabaseError(RuntimeError):
    """A safe, user-displayable persistence error."""


@contextmanager
def _connection(db_path: str | Path = DEFAULT_DB_PATH) -> Iterator[sqlite3.Connection]:
    connection: sqlite3.Connection | None = None
    try:
        path = Path(db_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        yield connection
        connection.commit()
    except sqlite3.Error as exc:
        if connection is not None:
            connection.rollback()
        raise DatabaseError("The local SentinelFlow database could not be updated.") from exc
    finally:
        if connection is not None:
            connection.close()


def init_db(db_path: str | Path = DEFAULT_DB_PATH) -> None:
    """Create the persistent schema, retaining existing records."""
    with _connection(db_path) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS api_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                client_id TEXT NOT NULL,
                http_method TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                status_code INTEGER NOT NULL,
                category TEXT NOT NULL,
                response_time_ms REAL NOT NULL,
                classification TEXT NOT NULL CHECK (classification IN ('Normal', 'Suspicious'))
            );
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON api_events(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_events_client ON api_events(client_id);
            CREATE TABLE IF NOT EXISTS security_incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                detection_rule TEXT NOT NULL,
                severity TEXT NOT NULL CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
                description TEXT NOT NULL,
                evidence TEXT NOT NULL,
                client_id TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Open' CHECK (status IN ('Open', 'Investigating', 'Resolved')),
                recommended_steps TEXT NOT NULL,
                dedupe_key TEXT NOT NULL UNIQUE
            );
            CREATE INDEX IF NOT EXISTS idx_incidents_status ON security_incidents(status);
            CREATE INDEX IF NOT EXISTS idx_incidents_timestamp ON security_incidents(timestamp DESC);
            """
        )


def _bounded_text(value: Any, field: str, *, limit: int = MAX_TEXT_LENGTH) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be text")
    cleaned = value.strip()
    if not cleaned or len(cleaned) > limit:
        raise ValueError(f"{field} must contain between 1 and {limit} characters")
    return cleaned


def _timestamp_string(value: Any) -> str:
    parsed = parse_utc_timestamp(value)
    if parsed is None:
        raise ValueError("timestamp must be a valid ISO-8601 value")
    return parsed.isoformat()


def _event_tuple(event: Mapping[str, Any]) -> tuple[Any, ...]:
    method = _bounded_text(event.get("http_method"), "HTTP method", limit=10).upper()
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
        raise ValueError("HTTP method is not supported")
    endpoint = _bounded_text(event.get("endpoint"), "endpoint")
    if not endpoint.startswith("/"):
        raise ValueError("endpoint must start with '/'")
    try:
        status_code = int(event.get("status_code"))
        response_time = float(event.get("response_time_ms"))
    except (TypeError, ValueError) as exc:
        raise ValueError("status code and response time must be numeric") from exc
    if not 100 <= status_code <= 599 or not 0 <= response_time <= 300_000:
        raise ValueError("event values are outside safe limits")
    classification = _bounded_text(event.get("classification", "Normal"), "classification", limit=20).title()
    if classification not in VALID_CLASSIFICATIONS:
        raise ValueError("classification must be Normal or Suspicious")
    return (
        _timestamp_string(event.get("timestamp")),
        _bounded_text(event.get("client_id"), "client ID", limit=100),
        method,
        endpoint,
        status_code,
        _bounded_text(event.get("category"), "category", limit=100),
        response_time,
        classification,
    )


def insert_events(events: Sequence[Mapping[str, Any]], db_path: str | Path = DEFAULT_DB_PATH) -> list[int]:
    """Validate and insert a batch atomically, returning generated IDs."""
    init_db(db_path)
    rows = [_event_tuple(event) for event in events]
    if not rows:
        return []
    with _connection(db_path) as conn:
        identifiers: list[int] = []
        for row in rows:
            cursor = conn.execute(
                """
                INSERT INTO api_events
                (timestamp, client_id, http_method, endpoint, status_code, category, response_time_ms, classification)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                row,
            )
            identifiers.append(int(cursor.lastrowid))
    return identifiers


def _parse_json(value: str, fallback: Any) -> Any:
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return fallback


def _rows_to_dicts(rows: Sequence[sqlite3.Row], *, incidents: bool = False) -> list[dict[str, Any]]:
    result = [dict(row) for row in rows]
    if incidents:
        for row in result:
            row["evidence"] = _parse_json(row["evidence"], {"raw": row["evidence"]})
            row["recommended_steps"] = _parse_json(row["recommended_steps"], [row["recommended_steps"]])
    return result


def get_events(
    db_path: str | Path = DEFAULT_DB_PATH,
    *,
    client_id: str | None = None,
    status_code: int | None = None,
    category: str | None = None,
    classification: str | None = None,
    date_start: str | None = None,
    date_end: str | None = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    """Fetch real event records using optional parameterized filters."""
    init_db(db_path)
    safe_limit = max(1, min(int(limit), 2_000))
    clauses: list[str] = []
    values: list[Any] = []
    if client_id:
        clauses.append("client_id = ?")
        values.append(_bounded_text(client_id, "client ID", limit=100))
    if status_code is not None:
        status = int(status_code)
        if not 100 <= status <= 599:
            raise ValueError("status code filter must be between 100 and 599")
        clauses.append("status_code = ?")
        values.append(status)
    if category:
        clauses.append("category = ?")
        values.append(_bounded_text(category, "category", limit=100))
    if classification:
        normalized = _bounded_text(classification, "classification", limit=20).title()
        if normalized not in VALID_CLASSIFICATIONS:
            raise ValueError("invalid classification filter")
        clauses.append("classification = ?")
        values.append(normalized)
    if date_start:
        clauses.append("timestamp >= ?")
        values.append(_timestamp_string(date_start))
    if date_end:
        clauses.append("timestamp <= ?")
        values.append(_timestamp_string(date_end))
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with _connection(db_path) as conn:
        rows = conn.execute(
            f"SELECT * FROM api_events{where} ORDER BY timestamp DESC LIMIT ?", [*values, safe_limit]
        ).fetchall()
    return _rows_to_dicts(rows)


def get_all_events(db_path: str | Path = DEFAULT_DB_PATH, *, limit: int = 10_000) -> list[dict[str, Any]]:
    return get_events(db_path, limit=limit)


def _incident_tuple(incident: Mapping[str, Any]) -> tuple[Any, ...]:
    severity = _bounded_text(incident.get("severity"), "severity", limit=20).title()
    if severity not in VALID_SEVERITIES:
        raise ValueError("invalid incident severity")
    evidence = incident.get("evidence", {})
    evidence_json = json.dumps(evidence, sort_keys=True, default=str)
    steps = incident.get("recommended_steps", [])
    if isinstance(steps, str):
        steps = [steps]
    if not isinstance(steps, list) or not all(isinstance(step, str) for step in steps):
        raise ValueError("recommended steps must be a list of text")
    steps_json = json.dumps(steps)
    if len(evidence_json) > MAX_EVIDENCE_LENGTH or len(steps_json) > MAX_EVIDENCE_LENGTH:
        raise ValueError("incident evidence exceeds safe size limits")
    return (
        _timestamp_string(incident.get("timestamp") or datetime.now(timezone.utc)),
        _bounded_text(incident.get("detection_rule") or incident.get("rule_identifier"), "detection rule", limit=100),
        severity,
        _bounded_text(incident.get("description"), "description", limit=1_000),
        evidence_json,
        _bounded_text(incident.get("client_id"), "client ID", limit=100),
        "Open",
        steps_json,
        _bounded_text(incident.get("dedupe_key"), "dedupe key", limit=128),
    )


def create_incidents(
    incidents: Sequence[Mapping[str, Any]], db_path: str | Path = DEFAULT_DB_PATH
) -> int:
    """Persist only previously unseen ongoing-detection alerts."""
    init_db(db_path)
    rows = [_incident_tuple(incident) for incident in incidents]
    inserted = 0
    if not rows:
        return inserted
    with _connection(db_path) as conn:
        for row in rows:
            cursor = conn.execute(
                """
                INSERT INTO security_incidents
                (timestamp, detection_rule, severity, description, evidence, client_id, status, recommended_steps, dedupe_key)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(dedupe_key) DO NOTHING
                """,
                row,
            )
            inserted += cursor.rowcount
    return inserted


def get_incidents(
    db_path: str | Path = DEFAULT_DB_PATH,
    *,
    severity: str | None = None,
    status: str | None = None,
    search: str | None = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    init_db(db_path)
    safe_limit = max(1, min(int(limit), 2_000))
    clauses: list[str] = []
    values: list[Any] = []
    if severity:
        normalized = _bounded_text(severity, "severity", limit=20).title()
        if normalized not in VALID_SEVERITIES:
            raise ValueError("invalid severity filter")
        clauses.append("severity = ?")
        values.append(normalized)
    if status:
        normalized = _bounded_text(status, "status", limit=20).title()
        if normalized not in VALID_STATUSES:
            raise ValueError("invalid status filter")
        clauses.append("status = ?")
        values.append(normalized)
    if search:
        safe_search = _bounded_text(search, "search", limit=100)
        clauses.append("(detection_rule LIKE ? OR description LIKE ? OR client_id LIKE ?)")
        values.extend([f"%{safe_search}%"] * 3)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with _connection(db_path) as conn:
        rows = conn.execute(
            f"SELECT * FROM security_incidents{where} ORDER BY timestamp DESC LIMIT ?", [*values, safe_limit]
        ).fetchall()
    return _rows_to_dicts(rows, incidents=True)


def update_incident_status(
    incident_id: int, status: str, db_path: str | Path = DEFAULT_DB_PATH
) -> bool:
    """Safely update a single incident, returning whether it existed."""
    init_db(db_path)
    if not isinstance(incident_id, int) or incident_id < 1:
        raise ValueError("incident ID must be a positive integer")
    normalized = _bounded_text(status, "status", limit=20).title()
    if normalized not in VALID_STATUSES:
        raise ValueError("status must be Open, Investigating, or Resolved")
    with _connection(db_path) as conn:
        cursor = conn.execute("UPDATE security_incidents SET status = ? WHERE id = ?", (normalized, incident_id))
    return cursor.rowcount == 1


def dashboard_metrics(db_path: str | Path = DEFAULT_DB_PATH) -> dict[str, int]:
    """Return dashboard figures calculated directly from stored rows."""
    init_db(db_path)
    with _connection(db_path) as conn:
        event_count = conn.execute("SELECT COUNT(*) FROM api_events").fetchone()[0]
        suspicious = conn.execute(
            "SELECT COUNT(*) FROM api_events WHERE classification = ?", ("Suspicious",)
        ).fetchone()[0]
        open_count = conn.execute(
            "SELECT COUNT(*) FROM security_incidents WHERE status != ?", ("Resolved",)
        ).fetchone()[0]
        critical = conn.execute(
            "SELECT COUNT(*) FROM security_incidents WHERE severity = ?", ("Critical",)
        ).fetchone()[0]
    return {
        "total_api_events": int(event_count),
        "suspicious_events": int(suspicious),
        "open_incidents": int(open_count),
        "critical_incidents": int(critical),
    }
