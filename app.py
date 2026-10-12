"""SentinelFlow local API security-monitoring dashboard."""

from __future__ import annotations

from datetime import datetime, time, timezone

import pandas as pd
import plotly.express as px
import streamlit as st

from database import (
    DEFAULT_DB_PATH,
    DatabaseError,
    dashboard_metrics,
    get_all_events,
    get_events,
    get_incidents,
    init_db,
    update_incident_status,
)
from simulator import SCENARIOS, run_scenario


st.set_page_config(page_title="SentinelFlow", page_icon="◈", layout="wide", initial_sidebar_state="expanded")

CUSTOM_CSS = """
<style>
    .stApp { background: #07111f; color: #d8e5f3; }
    [data-testid="stSidebar"] { background: #0b1728; border-right: 1px solid #20354e; }
    [data-testid="stMetric"] { background: linear-gradient(145deg, #0d2036, #091829); border: 1px solid #1d3b58; border-radius: 12px; padding: 17px; }
    [data-testid="stMetricLabel"] { color: #9fb6ce; }
    [data-testid="stMetricValue"] { color: #f1f7ff; }
    h1, h2, h3 { color: #eef7ff !important; }
    .eyebrow { color: #52d6b0; letter-spacing: .13em; font-size: .74rem; font-weight: 700; text-transform: uppercase; }
    .subtle { color: #a9bdd0; }
    .severity-high { color: #ff9e8f; font-weight: 700; }
    .severity-medium { color: #ffd17a; font-weight: 700; }
    .severity-critical { color: #ff6b87; font-weight: 700; }
    .severity-low { color: #6ed9f6; font-weight: 700; }
    .stButton > button { border-radius: 8px; border: 1px solid #2b6284; background: #123a56; color: #eef8ff; }
    .stButton > button:hover { border-color: #52d6b0; color: #52d6b0; }
    [data-testid="stDataFrame"] { border: 1px solid #1d3b58; border-radius: 8px; overflow: hidden; }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


def _frame(rows: list[dict]) -> pd.DataFrame:
    """Convert database dictionaries to a consistently typed data frame."""
    if not rows:
        return pd.DataFrame()
    frame = pd.DataFrame(rows)
    if "timestamp" in frame:
        frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True, errors="coerce")
    return frame


def _dark_figure(figure, height: int = 330):
    figure.update_layout(
        template="plotly_dark",
        paper_bgcolor="#0b1728",
        plot_bgcolor="#0b1728",
        font={"color": "#d8e5f3"},
        margin={"l": 12, "r": 12, "t": 42, "b": 12},
        height=height,
        legend_title_text="",
    )
    figure.update_xaxes(gridcolor="#1c3249")
    figure.update_yaxes(gridcolor="#1c3249")
    return figure


def _empty_state(message: str) -> None:
    st.info(message, icon="ℹ️")


def _event_volume_chart(events: pd.DataFrame, title: str):
    if events.empty or events["timestamp"].isna().all():
        return None
    series = events.dropna(subset=["timestamp"]).copy()
    series["period"] = series["timestamp"].dt.floor("min")
    grouped = series.groupby("period").size().reset_index(name="events")
    fig = px.line(grouped, x="period", y="events", markers=True, title=title, color_discrete_sequence=["#52d6b0"])
    return _dark_figure(fig)


def _severity_chart(incidents: pd.DataFrame, title: str):
    if incidents.empty:
        return None
    order = ["Critical", "High", "Medium", "Low"]
    grouped = incidents.groupby("severity").size().reindex(order, fill_value=0).reset_index(name="incidents")
    fig = px.bar(
        grouped, x="severity", y="incidents", title=title, color="severity",
        category_orders={"severity": order},
        color_discrete_map={"Critical": "#ff5577", "High": "#ff8d7a", "Medium": "#ffd166", "Low": "#67c7e8"},
    )
    return _dark_figure(fig)


def _category_chart(events: pd.DataFrame, title: str):
    if events.empty:
        return None
    grouped = events.groupby("category").size().reset_index(name="events").sort_values("events", ascending=False)
    fig = px.bar(grouped, x="category", y="events", title=title, color_discrete_sequence=["#688be8"])
    return _dark_figure(fig)


def _classification_chart(events: pd.DataFrame, title: str):
    if events.empty:
        return None
    grouped = events.groupby("classification").size().reset_index(name="events")
    fig = px.pie(
        grouped, names="classification", values="events", title=title,
        color="classification", color_discrete_map={"Normal": "#52d6b0", "Suspicious": "#ff9e8f"}, hole=0.48,
    )
    return _dark_figure(fig)


def _show_chart(figure, empty_message: str) -> None:
    if figure is None:
        _empty_state(empty_message)
    else:
        st.plotly_chart(figure, use_container_width=True, config={"displaylogo": False})


def render_dashboard() -> None:
    st.markdown("<p class='eyebrow'>Security operations overview</p>", unsafe_allow_html=True)
    st.title("SentinelFlow Dashboard")
    st.markdown("<p class='subtle'>Local API telemetry and heuristic threat indicators, backed by your SQLite records.</p>", unsafe_allow_html=True)
    metrics = dashboard_metrics(DEFAULT_DB_PATH)
    cards = st.columns(4)
    cards[0].metric("Total API Events", metrics["total_api_events"])
    cards[1].metric("Suspicious Events", metrics["suspicious_events"])
    cards[2].metric("Open Incidents", metrics["open_incidents"])
    cards[3].metric("Critical Incidents", metrics["critical_incidents"])

    events = _frame(get_all_events(DEFAULT_DB_PATH))
    incidents = _frame(get_incidents(DEFAULT_DB_PATH, limit=2_000))
    left, right = st.columns(2)
    with left:
        _show_chart(_event_volume_chart(events, "API traffic over time"), "Generate traffic in the simulator to see API volume.")
    with right:
        _show_chart(_severity_chart(incidents, "Incidents by severity"), "No incidents have been recorded yet.")
    left, right = st.columns(2)
    with left:
        _show_chart(_category_chart(events, "Events by category"), "No event categories are available yet.")
    with right:
        _show_chart(_classification_chart(events, "Normal vs suspicious events"), "No classifications are available yet.")


def render_simulator() -> None:
    st.markdown("<p class='eyebrow'>Synthetic traffic lab</p>", unsafe_allow_html=True)
    st.title("Traffic Simulator")
    st.caption("All scenarios generate local, synthetic records only. No external requests or real credentials are used.")
    for scenario, description in SCENARIOS.items():
        with st.container(border=True):
            label_col, action_col = st.columns([4, 1])
            with label_col:
                st.subheader(scenario)
                st.caption(description)
            with action_col:
                if st.button("Generate", key=f"simulate_{scenario}", use_container_width=True):
                    try:
                        outcome = run_scenario(scenario, str(DEFAULT_DB_PATH))
                    except (ValueError, DatabaseError) as exc:
                        st.error(f"Could not generate the scenario: {exc}")
                    else:
                        st.success(
                            f"Saved {outcome['event_count']} synthetic events and created "
                            f"{outcome['new_incident_count']} new incident(s)."
                        )
                        triggered = outcome["detected_incidents"]
                        if triggered:
                            st.warning("Triggered rules: " + ", ".join(item["detection_rule"] for item in triggered))
                        else:
                            st.info("No heuristic rule triggered for this scenario.")


def render_event_explorer() -> None:
    st.markdown("<p class='eyebrow'>Telemetry search</p>", unsafe_allow_html=True)
    st.title("Event Explorer")
    st.caption("Filters are applied to stored SQLite records. Results are capped at 500 rows for responsive browsing.")
    all_events = get_all_events(DEFAULT_DB_PATH, limit=2_000)
    all_frame = _frame(all_events)
    categories = sorted(all_frame["category"].dropna().unique().tolist()) if not all_frame.empty else []
    statuses = sorted(int(item) for item in all_frame["status_code"].dropna().unique()) if not all_frame.empty else []
    with st.form("event_filters"):
        first, second, third = st.columns(3)
        client_id = first.text_input("Client ID", max_chars=100)
        selected_status = second.selectbox("HTTP status", ["Any", *statuses])
        selected_category = third.selectbox("Category", ["Any", *categories])
        fourth, fifth = st.columns(2)
        selected_classification = fourth.selectbox("Classification", ["Any", "Normal", "Suspicious"])
        apply_dates = fifth.checkbox("Filter by UTC date range")
        start_date = end_date = None
        if apply_dates:
            start_date, end_date = st.date_input("Date range", value=(datetime.now(timezone.utc).date(), datetime.now(timezone.utc).date()))
        submitted = st.form_submit_button("Apply filters")
    if not submitted:
        client_id, selected_status, selected_category, selected_classification = "", "Any", "Any", "Any"
        start_date = end_date = None
    date_start = datetime.combine(start_date, time.min, tzinfo=timezone.utc).isoformat() if start_date else None
    date_end = datetime.combine(end_date, time.max, tzinfo=timezone.utc).isoformat() if end_date else None
    try:
        events = get_events(
            DEFAULT_DB_PATH,
            client_id=client_id or None,
            status_code=None if selected_status == "Any" else int(selected_status),
            category=None if selected_category == "Any" else selected_category,
            classification=None if selected_classification == "Any" else selected_classification,
            date_start=date_start,
            date_end=date_end,
            limit=500,
        )
    except (ValueError, DatabaseError) as exc:
        st.error(f"Unable to load events: {exc}")
        return
    if not events:
        _empty_state("No events match the selected filters. Generate a simulator scenario or broaden the search.")
        return
    event_frame = _frame(events)
    display = event_frame.copy()
    display["timestamp"] = display["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    st.dataframe(display, use_container_width=True, hide_index=True, height=390)
    ids = [int(item["id"]) for item in events]
    selected_id = st.selectbox("Inspect event details", ids, format_func=lambda value: f"Event #{value}")
    event = next(item for item in events if int(item["id"]) == selected_id)
    st.json(event, expanded=False)


def render_incident_management() -> None:
    st.markdown("<p class='eyebrow'>Case workflow</p>", unsafe_allow_html=True)
    st.title("Incident Management")
    st.caption("Status changes are persisted in SQLite. Heuristics are indicators for investigation, not proof of an attack.")
    filters = st.columns(3)
    search = filters[0].text_input("Search rule, client, or description", max_chars=100)
    severity = filters[1].selectbox("Severity", ["Any", "Critical", "High", "Medium", "Low"])
    status = filters[2].selectbox("Status", ["Any", "Open", "Investigating", "Resolved"])
    try:
        incidents = get_incidents(
            DEFAULT_DB_PATH, severity=None if severity == "Any" else severity,
            status=None if status == "Any" else status, search=search or None, limit=500,
        )
    except (ValueError, DatabaseError) as exc:
        st.error(f"Unable to load incidents: {exc}")
        return
    if not incidents:
        _empty_state("No incident records match this view. Run a suspicious simulator scenario to create one.")
        return
    summary = _frame(incidents).drop(columns=["evidence", "recommended_steps", "dedupe_key"], errors="ignore")
    summary["timestamp"] = summary["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    st.dataframe(summary, use_container_width=True, hide_index=True, height=300)
    incident_ids = [int(item["id"]) for item in incidents]
    selected_id = st.selectbox("Open incident", incident_ids, format_func=lambda value: f"Incident #{value}")
    incident = next(item for item in incidents if int(item["id"]) == selected_id)
    with st.expander("Incident evidence and investigation guide", expanded=True):
        st.markdown(f"**Rule:** `{incident['detection_rule']}`  ")
        st.markdown(f"**Client:** `{incident['client_id']}`  ")
        st.markdown(f"**Description:** {incident['description']}")
        st.markdown("**Evidence**")
        st.json(incident["evidence"], expanded=False)
        st.markdown("**Recommended investigation steps**")
        for step in incident["recommended_steps"]:
            st.write(f"• {step}")
    new_status = st.selectbox("Update incident status", ["Open", "Investigating", "Resolved"], index=["Open", "Investigating", "Resolved"].index(incident["status"]))
    if st.button("Save status", type="primary"):
        try:
            changed = update_incident_status(selected_id, new_status, DEFAULT_DB_PATH)
        except (ValueError, DatabaseError) as exc:
            st.error(f"Status was not updated: {exc}")
        else:
            if changed:
                st.success(f"Incident #{selected_id} is now {new_status}.")
                st.rerun()
            else:
                st.warning("The selected incident no longer exists.")


def render_analytics() -> None:
    st.markdown("<p class='eyebrow'>Stored-data analytics</p>", unsafe_allow_html=True)
    st.title("Analytics")
    events = _frame(get_all_events(DEFAULT_DB_PATH))
    incidents = _frame(get_incidents(DEFAULT_DB_PATH, limit=2_000))
    first, second = st.columns(2)
    with first:
        _show_chart(_event_volume_chart(events, "Event volume over time"), "No events are available for trend analysis.")
    with second:
        if events.empty:
            _empty_state("No suspicious-event categories are available yet.")
        else:
            suspicious = events[events["classification"] == "Suspicious"]
            _show_chart(_category_chart(suspicious, "Suspicious events by category"), "No suspicious events are recorded yet.")
    third, fourth = st.columns(2)
    with third:
        _show_chart(_severity_chart(incidents, "Incidents by severity"), "No incidents are available for severity analysis.")
    with fourth:
        if incidents.empty:
            _empty_state("No incident statuses are available yet.")
        else:
            status_counts = incidents.groupby("status").size().reset_index(name="incidents")
            fig = px.pie(status_counts, names="status", values="incidents", hole=.45, title="Open vs resolved incidents", color="status", color_discrete_map={"Open": "#ff8d7a", "Investigating": "#ffd166", "Resolved": "#52d6b0"})
            _show_chart(_dark_figure(fig), "No incident statuses are available yet.")
    if incidents.empty:
        _empty_state("No detection-rule frequency is available yet.")
    else:
        frequency = incidents.groupby("detection_rule").size().reset_index(name="incidents").sort_values("incidents", ascending=False)
        fig = px.bar(frequency, x="detection_rule", y="incidents", title="Detection rule frequency", color_discrete_sequence=["#8f7bea"])
        _show_chart(_dark_figure(fig), "No detection rules have triggered yet.")


def render_about() -> None:
    st.markdown("<p class='eyebrow'>Educational prototype</p>", unsafe_allow_html=True)
    st.title("About SentinelFlow")
    st.markdown(
        """
        SentinelFlow is a local API-security monitoring MVP built with Streamlit,
        SQLite, Pandas, and Plotly. It records synthetic event telemetry and applies
        transparent, configurable heuristics for failed-login bursts, request-rate
        spikes, endpoint scanning, and server-error bursts.

        **Important:** This is not a production SOC platform. Its rules are heuristic
        indicators only; they should be validated against application context before
        any operational conclusion or response. The simulator uses synthetic data and
        never makes a network request.
        """
    )
    st.code(f"Local database: {DEFAULT_DB_PATH.name}", language=None)


def main() -> None:
    try:
        init_db(DEFAULT_DB_PATH)
    except DatabaseError as exc:
        st.error(f"SentinelFlow could not initialise its local database: {exc}")
        st.stop()
    st.sidebar.markdown("## ◈ SENTINFLOW")
    st.sidebar.caption("API Security Monitoring")
    page = st.sidebar.radio("Navigate", ["Dashboard", "Traffic Simulator", "Event Explorer", "Incident Management", "Analytics", "About"])
    st.sidebar.divider()
    st.sidebar.caption("Local • Synthetic data only • UTC timestamps")
    try:
        {
            "Dashboard": render_dashboard,
            "Traffic Simulator": render_simulator,
            "Event Explorer": render_event_explorer,
            "Incident Management": render_incident_management,
            "Analytics": render_analytics,
            "About": render_about,
        }[page]()
    except DatabaseError as exc:
        st.error(f"A local database operation failed safely: {exc}")


if __name__ == "__main__":
    main()
