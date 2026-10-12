"""Deterministic, entirely local synthetic API telemetry scenarios."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from random import Random
from typing import Any

from database import DEFAULT_DB_PATH, create_incidents, insert_events
from detection_engine import run_detections


SCENARIOS = {
    "Normal traffic": "A spread of healthy application calls.",
    "Failed login burst": "Repeated failed authentication from a simulated client.",
    "Excessive request rate": "A short high-volume burst from a simulated client.",
    "Endpoint scanning": "Repeated requests to unavailable routes.",
    "Server error burst": "Repeated application 5xx responses for review.",
}


def _event(
    timestamp: datetime,
    client_id: str,
    method: str,
    endpoint: str,
    status: int,
    category: str,
    response_time_ms: float,
    classification: str,
) -> dict[str, Any]:
    return {
        "timestamp": timestamp.astimezone(timezone.utc).isoformat(),
        "client_id": client_id,
        "http_method": method,
        "endpoint": endpoint,
        "status_code": status,
        "category": category,
        "response_time_ms": round(response_time_ms, 2),
        "classification": classification,
    }


def generate_scenario(name: str, *, now: datetime | None = None) -> list[dict[str, Any]]:
    """Generate reproducible synthetic records.  No network calls are made."""
    if name not in SCENARIOS:
        raise ValueError("unknown simulator scenario")
    base = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)
    rng = Random(42)
    events: list[dict[str, Any]] = []
    if name == "Normal traffic":
        routes = [("GET", "/v1/orders", "Orders"), ("GET", "/v1/inventory", "Inventory"), ("POST", "/v1/orders", "Orders")]
        for index in range(12):
            method, endpoint, category = routes[index % len(routes)]
            events.append(
                _event(
                    base - timedelta(minutes=11 - index),
                    f"app-client-{(index % 3) + 1}", method, endpoint, 200, category,
                    rng.uniform(55, 260), "Normal",
                )
            )
    elif name == "Failed login burst":
        for index in range(6):
            events.append(_event(base - timedelta(seconds=5 * (5 - index)), "sim-auth-17", "POST", "/v1/auth/login", 401, "Authentication", 85 + index, "Suspicious"))
    elif name == "Excessive request rate":
        for index in range(18):
            events.append(_event(base - timedelta(seconds=2 * (17 - index)), "sim-rate-42", "GET", "/v1/telemetry", 200, "Telemetry", 34 + index, "Suspicious"))
    elif name == "Endpoint scanning":
        for index in range(6):
            events.append(_event(base - timedelta(seconds=12 * (5 - index)), "sim-scan-08", "GET", f"/v1/unknown/resource-{index + 1}", 404, "Routing", 21 + index, "Suspicious"))
    elif name == "Server error burst":
        for index in range(5):
            events.append(_event(base - timedelta(seconds=15 * (4 - index)), "sim-error-73", "POST", "/v1/payments/charge", 503, "Payments", 900 + index * 30, "Suspicious"))
    return events


def run_scenario(name: str, db_path: str = str(DEFAULT_DB_PATH)) -> dict[str, Any]:
    """Store a scenario, execute all detections, and persist new incidents."""
    events = generate_scenario(name)
    event_ids = insert_events(events, db_path)
    for event, event_id in zip(events, event_ids):
        event["id"] = event_id
    detected = run_detections(events)
    new_incidents = create_incidents(detected, db_path)
    return {
        "scenario": name,
        "event_count": len(events),
        "event_ids": event_ids,
        "detected_incidents": detected,
        "new_incident_count": new_incidents,
    }
