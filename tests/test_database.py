from datetime import datetime, timezone

from database import (
    create_incidents,
    dashboard_metrics,
    get_events,
    get_incidents,
    init_db,
    insert_events,
    update_incident_status,
)
from detection_engine import run_detections


def sample_event():
    return {
        "timestamp": datetime(2026, 1, 1, tzinfo=timezone.utc).isoformat(),
        "client_id": "test-client",
        "http_method": "GET",
        "endpoint": "/v1/orders",
        "status_code": 200,
        "category": "Orders",
        "response_time_ms": 42.5,
        "classification": "Normal",
    }


def sample_incident():
    return {
        "timestamp": datetime(2026, 1, 1, tzinfo=timezone.utc).isoformat(),
        "detection_rule": "TEST_RULE",
        "severity": "Medium",
        "description": "Test alert for persistence verification.",
        "evidence": {"count": 5},
        "client_id": "test-client",
        "recommended_steps": ["Review test data."],
        "dedupe_key": "test-rule-client-unique-key",
    }


def test_sqlite_event_persistence_and_metrics(tmp_path):
    db_path = tmp_path / "isolated.db"
    init_db(db_path)
    identifiers = insert_events([sample_event()], db_path)
    rows = get_events(db_path)
    assert len(identifiers) == 1
    assert len(rows) == 1
    assert rows[0]["endpoint"] == "/v1/orders"
    assert dashboard_metrics(db_path)["total_api_events"] == 1


def test_duplicate_incident_prevention(tmp_path):
    db_path = tmp_path / "isolated.db"
    incident = sample_incident()
    assert create_incidents([incident], db_path) == 1
    assert create_incidents([incident], db_path) == 0
    assert len(get_incidents(db_path)) == 1


def test_incident_status_update_persists(tmp_path):
    db_path = tmp_path / "isolated.db"
    create_incidents([sample_incident()], db_path)
    incident_id = get_incidents(db_path)[0]["id"]
    assert update_incident_status(incident_id, "Investigating", db_path) is True
    assert get_incidents(db_path)[0]["status"] == "Investigating"
    assert update_incident_status(999_999, "Resolved", db_path) is False


def test_same_detected_events_create_one_persisted_incident(tmp_path):
    db_path = tmp_path / "isolated.db"
    events = []
    for index in range(5):
        item = sample_event() | {
            "timestamp": datetime(2026, 1, 1, 0, index, tzinfo=timezone.utc).isoformat(),
            "status_code": 401,
            "category": "Authentication",
            "endpoint": "/v1/auth/login",
            "classification": "Suspicious",
        }
        events.append(item)
    ids = insert_events(events, db_path)
    for item, identifier in zip(events, ids):
        item["id"] = identifier
    alerts = run_detections(events)
    login_alerts = [item for item in alerts if item["detection_rule"] == "FAILED_LOGIN_BURST"]
    assert len(login_alerts) == 1
    assert create_incidents(login_alerts, db_path) == 1
    assert create_incidents(login_alerts, db_path) == 0
