from datetime import datetime, timedelta, timezone

from detection_engine import (
    DetectionConfig,
    detect_endpoint_scanning,
    detect_excessive_request_rate,
    detect_failed_login_bursts,
    detect_server_error_bursts,
    run_detections,
)


BASE_TIME = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def event(offset_seconds, *, client="client-a", status=200, category="Orders", endpoint="/v1/orders"):
    return {
        "timestamp": (BASE_TIME + timedelta(seconds=offset_seconds)).isoformat(),
        "client_id": client,
        "http_method": "GET",
        "endpoint": endpoint,
        "status_code": status,
        "category": category,
        "response_time_ms": 30,
        "classification": "Normal",
    }


def test_failed_login_detection():
    events = [event(i * 10, status=401, category="Authentication", endpoint="/v1/auth/login") for i in range(5)]
    alerts = detect_failed_login_bursts(events)
    assert len(alerts) == 1
    assert alerts[0]["detection_rule"] == "FAILED_LOGIN_BURST"
    assert alerts[0]["severity"] == "High"
    assert alerts[0]["evidence"]["event_count"] == 5


def test_request_rate_detection():
    config = DetectionConfig(request_rate_threshold=4, request_rate_window_seconds=30)
    alerts = detect_excessive_request_rate([event(i * 5) for i in range(4)], config)
    assert len(alerts) == 1
    assert alerts[0]["detection_rule"] == "EXCESSIVE_REQUEST_RATE"


def test_endpoint_scanning_detection():
    events = [event(i * 10, status=404, endpoint=f"/missing/{i}") for i in range(5)]
    alerts = detect_endpoint_scanning(events)
    assert len(alerts) == 1
    assert alerts[0]["detection_rule"] == "ENDPOINT_SCANNING"


def test_server_error_detection():
    events = [event(i * 10, status=503, endpoint="/v1/payments") for i in range(4)]
    alerts = detect_server_error_bursts(events)
    assert len(alerts) == 1
    assert alerts[0]["detection_rule"] == "SERVER_ERROR_BURST"


def test_below_threshold_and_empty_input_do_not_alert():
    failures = [event(i * 10, status=401, category="Authentication") for i in range(4)]
    assert detect_failed_login_bursts(failures) == []
    assert run_detections([]) == []
    assert detect_excessive_request_rate([]) == []


def test_one_alert_per_client_for_an_ongoing_burst():
    config = DetectionConfig(request_rate_threshold=3, request_rate_window_seconds=60)
    alerts = detect_excessive_request_rate([event(i * 2) for i in range(10)], config)
    assert len(alerts) == 1
    assert len(alerts[0]["recommended_steps"]) >= 2
