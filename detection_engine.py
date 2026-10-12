"""Pure heuristic detection logic for SentinelFlow.

The functions in this module intentionally accept ordinary dictionaries and do
not know about SQLite or Streamlit.  These alerts are indicators for review,
not a determination of malicious activity.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Any, Callable, Iterable


UTC = timezone.utc


@dataclass(frozen=True)
class DetectionConfig:
    """Thresholds used by the four lightweight monitoring rules."""

    failed_login_threshold: int = 5
    failed_login_window_minutes: int = 5
    request_rate_threshold: int = 15
    request_rate_window_seconds: int = 60
    endpoint_scan_threshold: int = 5
    endpoint_scan_window_minutes: int = 5
    server_error_threshold: int = 4
    server_error_window_minutes: int = 5


def parse_utc_timestamp(value: Any) -> datetime | None:
    """Return an aware UTC datetime or ``None`` for malformed values."""
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _sorted_events(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    parsed: list[dict[str, Any]] = []
    for event in events:
        if not isinstance(event, dict) or not event.get("client_id"):
            continue
        timestamp = parse_utc_timestamp(event.get("timestamp"))
        if timestamp is not None:
            parsed.append({**event, "_parsed_timestamp": timestamp})
    return sorted(parsed, key=lambda row: row["_parsed_timestamp"])


def _build_incident(
    *,
    rule: str,
    client_id: str,
    severity: str,
    description: str,
    evidence: dict[str, Any],
    recommended_steps: list[str],
    detected_at: datetime,
    window_seconds: int,
) -> dict[str, Any]:
    """Build a stable alert representation, including an ongoing-alert key."""
    bucket = int(detected_at.timestamp()) // max(window_seconds, 1)
    key_material = f"{rule}|{client_id}|{bucket}".encode("utf-8")
    dedupe_key = sha256(key_material).hexdigest()
    return {
        "rule_identifier": rule,
        "detection_rule": rule,
        "timestamp": detected_at.isoformat(),
        "description": description,
        "severity": severity,
        "evidence": evidence,
        "client_id": client_id,
        "recommended_steps": recommended_steps,
        "dedupe_key": dedupe_key,
    }


def _first_threshold_windows(
    events: list[dict[str, Any]],
    threshold: int,
    window: timedelta,
) -> dict[str, list[dict[str, Any]]]:
    """Find at most one qualifying rolling window per client.

    Returning one result per client keeps a continuing burst from producing a
    storm of duplicate alerts during a single processing pass.
    """
    if threshold < 1:
        raise ValueError("threshold must be at least 1")
    grouped: dict[str, deque[dict[str, Any]]] = defaultdict(deque)
    matches: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        client_id = str(event["client_id"])
        if client_id in matches:
            continue
        active = grouped[client_id]
        active.append(event)
        cutoff = event["_parsed_timestamp"] - window
        while active and active[0]["_parsed_timestamp"] < cutoff:
            active.popleft()
        if len(active) >= threshold:
            matches[client_id] = list(active)
    return matches


def _detect_windowed(
    events: Iterable[dict[str, Any]],
    *,
    predicate: Callable[[dict[str, Any]], bool],
    threshold: int,
    window: timedelta,
    rule: str,
    severity: str,
    label: str,
    recommended_steps: list[str],
) -> list[dict[str, Any]]:
    relevant = [event for event in _sorted_events(events) if predicate(event)]
    matches = _first_threshold_windows(relevant, threshold, window)
    incidents: list[dict[str, Any]] = []
    for client_id, window_events in matches.items():
        end = window_events[-1]["_parsed_timestamp"]
        start = window_events[0]["_parsed_timestamp"]
        evidence = {
            "event_count": len(window_events),
            "threshold": threshold,
            "window_seconds": int(window.total_seconds()),
            "window_start": start.isoformat(),
            "window_end": end.isoformat(),
            "event_ids": [event["id"] for event in window_events if event.get("id") is not None],
            "sample_endpoints": list(dict.fromkeys(str(event.get("endpoint", "")) for event in window_events))[:5],
        }
        incidents.append(
            _build_incident(
                rule=rule,
                client_id=client_id,
                severity=severity,
                description=(
                    f"{label}: {len(window_events)} matching events from client "
                    f"{client_id} within {int(window.total_seconds())} seconds."
                ),
                evidence=evidence,
                recommended_steps=recommended_steps,
                detected_at=end,
                window_seconds=int(window.total_seconds()),
            )
        )
    return incidents


def detect_failed_login_bursts(
    events: Iterable[dict[str, Any]], config: DetectionConfig | None = None
) -> list[dict[str, Any]]:
    """Detect repeated 401/403 authentication failures per client."""
    cfg = config or DetectionConfig()
    return _detect_windowed(
        events,
        predicate=lambda event: (
            str(event.get("category", "")).lower() in {"authentication", "failed login"}
            and int(event.get("status_code", 0) or 0) in {401, 403}
        ),
        threshold=cfg.failed_login_threshold,
        window=timedelta(minutes=cfg.failed_login_window_minutes),
        rule="FAILED_LOGIN_BURST",
        severity="High",
        label="Failed login burst",
        recommended_steps=[
            "Review the client identity and authentication logs.",
            "Check whether the source is expected or recently changed credentials.",
            "Apply a temporary rate limit or credential-reset workflow if warranted.",
        ],
    )


def detect_excessive_request_rate(
    events: Iterable[dict[str, Any]], config: DetectionConfig | None = None
) -> list[dict[str, Any]]:
    """Detect a client exceeding the request count in a rolling interval."""
    cfg = config or DetectionConfig()
    return _detect_windowed(
        events,
        predicate=lambda _event: True,
        threshold=cfg.request_rate_threshold,
        window=timedelta(seconds=cfg.request_rate_window_seconds),
        rule="EXCESSIVE_REQUEST_RATE",
        severity="Medium",
        label="Excessive request rate",
        recommended_steps=[
            "Compare the request pattern with the client’s expected baseline.",
            "Inspect endpoints and response codes for automation or retry loops.",
            "Consider a scoped rate limit while the activity is investigated.",
        ],
    )


def detect_endpoint_scanning(
    events: Iterable[dict[str, Any]], config: DetectionConfig | None = None
) -> list[dict[str, Any]]:
    """Detect a run of requests returning 404 for a single client."""
    cfg = config or DetectionConfig()
    return _detect_windowed(
        events,
        predicate=lambda event: int(event.get("status_code", 0) or 0) == 404,
        threshold=cfg.endpoint_scan_threshold,
        window=timedelta(minutes=cfg.endpoint_scan_window_minutes),
        rule="ENDPOINT_SCANNING",
        severity="Medium",
        label="Endpoint scanning indicator",
        recommended_steps=[
            "Review the requested paths for reconnaissance-like patterns.",
            "Validate whether a deployed client is using an outdated API route.",
            "Check source ownership and tighten route-level monitoring if needed.",
        ],
    )


def detect_server_error_bursts(
    events: Iterable[dict[str, Any]], config: DetectionConfig | None = None
) -> list[dict[str, Any]]:
    """Detect repeated HTTP 5xx responses per client."""
    cfg = config or DetectionConfig()
    return _detect_windowed(
        events,
        predicate=lambda event: 500 <= int(event.get("status_code", 0) or 0) <= 599,
        threshold=cfg.server_error_threshold,
        window=timedelta(minutes=cfg.server_error_window_minutes),
        rule="SERVER_ERROR_BURST",
        severity="High",
        label="Server error burst",
        recommended_steps=[
            "Correlate the requests with application and infrastructure logs.",
            "Assess service health, recent releases, and dependency failures.",
            "Escalate operational impact if the error rate affects other clients.",
        ],
    )


def run_detections(
    events: Iterable[dict[str, Any]], config: DetectionConfig | None = None
) -> list[dict[str, Any]]:
    """Run every heuristic rule against an event batch."""
    materialized = list(events)
    if not materialized:
        return []
    return [
        *detect_failed_login_bursts(materialized, config),
        *detect_excessive_request_rate(materialized, config),
        *detect_endpoint_scanning(materialized, config),
        *detect_server_error_bursts(materialized, config),
    ]
