"""
SSH-HoneyGuard Security Dashboard - Milestone 2.

Read-only security monitoring dashboard.
The SQLite database is opened in application-level read-only mode.
No attacker commands are executed and no honeypot records are modified.
"""

import sqlite3
from collections import Counter

import streamlit as st


DB_PATH = "/app/data/honeyguard.db"


st.set_page_config(
    page_title="SSH-HoneyGuard Security Dashboard",
    page_icon="🛡️",
    layout="wide",
)


def get_connection():
    return sqlite3.connect(
        f"file:{DB_PATH}?mode=ro",
        uri=True,
    )


def fetch_all(query, params=()):
    conn = get_connection()
    try:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


@st.cache_data(ttl=5)
def load_data():
    sessions = fetch_all(
        """
        SELECT
            id,
            session_id,
            source_ip,
            source_port,
            started_at,
            ended_at,
            outcome
        FROM sessions
        ORDER BY id DESC
        """
    )

    authentication = fetch_all(
        """
        SELECT
            id,
            session_id,
            source_ip,
            source_port,
            username,
            method,
            result,
            password,
            timestamp
        FROM authentication_attempts
        ORDER BY id DESC
        """
    )

    commands = fetch_all(
        """
        SELECT
            id,
            session_id,
            source_ip,
            source_port,
            command_text,
            category,
            response_text,
            timestamp
        FROM commands
        ORDER BY id DESC
        """
    )

    alerts = fetch_all(
        """
        SELECT
            id,
            alert_id,
            session_id,
            source_ip,
            severity,
            alert_type,
            reason,
            evidence,
            timestamp
        FROM alerts
        ORDER BY id DESC
        """
    )

    return sessions, authentication, commands, alerts


try:
    sessions, authentication, commands, alerts = load_data()
except Exception as exc:
    st.error(f"Unable to read the honeypot database: {exc}")
    st.stop()


# ---------------------------------------------------------
# Header
# ---------------------------------------------------------

st.title("SSH-HoneyGuard Security Dashboard")
if st.button("🔄 Refresh Dashboard"):
    st.cache_data.clear()
    st.rerun()

st.caption(
    "Real-time security monitoring for the SSH honeypot. "
    "Dashboard access is read-only."
)


# ---------------------------------------------------------
# Sidebar filters
# ---------------------------------------------------------

st.sidebar.header("Dashboard Filters")

all_ips = sorted(
    set(
        [row["source_ip"] for row in sessions]
        + [row["source_ip"] for row in authentication]
        + [row["source_ip"] for row in commands]
        + [row["source_ip"] for row in alerts]
    )
)

all_categories = sorted(
    set(row["category"] for row in commands)
)

all_severities = sorted(
    set(row["severity"] for row in alerts)
)

all_alert_types = sorted(
    set(row["alert_type"] for row in alerts)
)


selected_ip = st.sidebar.selectbox(
    "Source IP",
    ["All"] + all_ips,
)

selected_category = st.sidebar.selectbox(
    "Command Category",
    ["All"] + all_categories,
)

selected_severity = st.sidebar.selectbox(
    "Alert Severity",
    ["All"] + all_severities,
)

selected_alert_type = st.sidebar.selectbox(
    "Alert Type",
    ["All"] + all_alert_types,
)


# ---------------------------------------------------------
# Apply filters
# ---------------------------------------------------------

filtered_sessions = sessions
filtered_authentication = authentication
filtered_commands = commands
filtered_alerts = alerts


if selected_ip != "All":
    filtered_sessions = [
        row for row in filtered_sessions
        if row["source_ip"] == selected_ip
    ]

    filtered_authentication = [
        row for row in filtered_authentication
        if row["source_ip"] == selected_ip
    ]

    filtered_commands = [
        row for row in filtered_commands
        if row["source_ip"] == selected_ip
    ]

    filtered_alerts = [
        row for row in filtered_alerts
        if row["source_ip"] == selected_ip
    ]


if selected_category != "All":
    filtered_commands = [
        row for row in filtered_commands
        if row["category"] == selected_category
    ]


if selected_severity != "All":
    filtered_alerts = [
        row for row in filtered_alerts
        if row["severity"] == selected_severity
    ]


if selected_alert_type != "All":
    filtered_alerts = [
        row for row in filtered_alerts
        if row["alert_type"] == selected_alert_type
    ]


# ---------------------------------------------------------
# Security overview metrics
# ---------------------------------------------------------

st.subheader("Security Overview")

col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "SSH Sessions",
    len(filtered_sessions),
)

col2.metric(
    "Authentication Attempts",
    len(filtered_authentication),
)

col3.metric(
    "Commands Captured",
    len(filtered_commands),
)

col4.metric(
    "Security Alerts",
    len(filtered_alerts),
)


st.divider()


# ---------------------------------------------------------
# Command analysis

import altair as alt
import pandas as pd

st.subheader("Security Analytics")

# ---------------------------------------------------------
# Command categories + alert severity
# ---------------------------------------------------------

col1, col2 = st.columns(2)

with col1:
    st.markdown("### Command Activity by Category")

    category_counts = Counter(
        row["category"] for row in filtered_commands
    )

    if category_counts:
        category_data = pd.DataFrame(
            [
                {"Category": category, "Count": count}
                for category, count in category_counts.items()
            ]
        ).sort_values("Count", ascending=False)

        category_chart = (
            alt.Chart(category_data)
            .mark_bar(cornerRadiusEnd=6)
            .encode(
                y=alt.Y(
                    "Category:N",
                    sort="-x",
                    title=None,
                ),
                x=alt.X(
                    "Count:Q",
                    title="Captured Commands",
                    axis=alt.Axis(format="d"),
                ),
                tooltip=[
                    alt.Tooltip("Category:N", title="Category"),
                    alt.Tooltip("Count:Q", title="Commands", format="d"),
                ],
            )
            .properties(height=330)
        )

        st.altair_chart(category_chart, use_container_width=True)
    else:
        st.info("No command data matches the selected filters.")


with col2:
    st.markdown("### Alert Severity Distribution")

    severity_counts = Counter(
        row["severity"] for row in filtered_alerts
    )

    if severity_counts:
        severity_data = pd.DataFrame(
            [
                {"Severity": severity, "Count": count}
                for severity, count in severity_counts.items()
            ]
        )

        severity_chart = (
            alt.Chart(severity_data)
            .mark_arc(innerRadius=65)
            .encode(
                theta=alt.Theta(
                    "Count:Q",
                    title="Alert Count",
                ),
                color=alt.Color(
                    "Severity:N",
                    title="Severity",
                ),
                tooltip=[
                    alt.Tooltip("Severity:N", title="Severity"),
                    alt.Tooltip("Count:Q", title="Alerts", format="d"),
                ],
            )
            .properties(height=330)
        )

        st.altair_chart(severity_chart, use_container_width=True)
    else:
        st.info("No alert data matches the selected filters.")


# ---------------------------------------------------------
# Alert type analysis
# ---------------------------------------------------------

st.markdown("### Alert Type Analysis")

alert_type_counts = Counter(
    row["alert_type"] for row in filtered_alerts
)

if alert_type_counts:
    alert_type_data = pd.DataFrame(
        [
            {"Alert Type": alert_type, "Count": count}
            for alert_type, count in alert_type_counts.items()
        ]
    ).sort_values("Count", ascending=False)

    alert_type_chart = (
        alt.Chart(alert_type_data)
        .mark_bar(cornerRadiusEnd=6)
        .encode(
            y=alt.Y(
                "Alert Type:N",
                sort="-x",
                title=None,
            ),
            x=alt.X(
                "Count:Q",
                title="Alert Count",
                axis=alt.Axis(format="d"),
            ),
            tooltip=[
                alt.Tooltip("Alert Type:N", title="Alert Type"),
                alt.Tooltip("Count:Q", title="Alerts", format="d"),
            ],
        )
        .properties(
            height=max(280, min(520, len(alert_type_data) * 42))
        )
    )

    st.altair_chart(alert_type_chart, use_container_width=True)
else:
    st.info("No alert types match the selected filters.")


# ---------------------------------------------------------
# Time-based security activity
# ---------------------------------------------------------

col3, col4 = st.columns(2)

with col3:
    st.markdown("### Command Activity Over Time")

    command_times = pd.DataFrame(
        [
            {"Timestamp": row["timestamp"]}
            for row in filtered_commands
            if row["timestamp"]
        ]
    )

    if not command_times.empty:
        command_times["Timestamp"] = pd.to_datetime(
            command_times["Timestamp"],
            errors="coerce",
        )
        command_times = command_times.dropna()

        if not command_times.empty:
            command_activity = (
                command_times
                .assign(
                    Period=lambda df: df["Timestamp"].dt.floor("h")
                )
                .groupby("Period")
                .size()
                .reset_index(name="Commands")
            )

            command_line = (
                alt.Chart(command_activity)
                .mark_line(point=True)
                .encode(
                    x=alt.X(
                        "Period:T",
                        title="Time",
                    ),
                    y=alt.Y(
                        "Commands:Q",
                        title="Captured Commands",
                        axis=alt.Axis(format="d"),
                    ),
                    tooltip=[
                        alt.Tooltip(
                            "Period:T",
                            title="Time",
                            format="%d %b %Y %H:%M",
                        ),
                        alt.Tooltip(
                            "Commands:Q",
                            title="Commands",
                            format="d",
                        ),
                    ],
                )
                .properties(height=320)
                .interactive()
            )

            st.altair_chart(
                command_line,
                use_container_width=True,
            )
        else:
            st.info("No valid command timestamps are available.")
    else:
        st.info("No command activity matches the selected filters.")


with col4:
    st.markdown("### Alert Activity Over Time")

    alert_times = pd.DataFrame(
        [
            {"Timestamp": row["timestamp"]}
            for row in filtered_alerts
            if row["timestamp"]
        ]
    )

    if not alert_times.empty:
        alert_times["Timestamp"] = pd.to_datetime(
            alert_times["Timestamp"],
            errors="coerce",
        )
        alert_times = alert_times.dropna()

        if not alert_times.empty:
            alert_activity = (
                alert_times
                .assign(
                    Period=lambda df: df["Timestamp"].dt.floor("h")
                )
                .groupby("Period")
                .size()
                .reset_index(name="Alerts")
            )

            alert_area = (
                alt.Chart(alert_activity)
                .mark_area(
                    line=True,
                    point=True,
                    opacity=0.45,
                )
                .encode(
                    x=alt.X(
                        "Period:T",
                        title="Time",
                    ),
                    y=alt.Y(
                        "Alerts:Q",
                        title="Security Alerts",
                        axis=alt.Axis(format="d"),
                    ),
                    tooltip=[
                        alt.Tooltip(
                            "Period:T",
                            title="Time",
                            format="%d %b %Y %H:%M",
                        ),
                        alt.Tooltip(
                            "Alerts:Q",
                            title="Alerts",
                            format="d",
                        ),
                    ],
                )
                .properties(height=320)
                .interactive()
            )

            st.altair_chart(
                alert_area,
                use_container_width=True,
            )
        else:
            st.info("No valid alert timestamps are available.")
    else:
        st.info("No alert activity matches the selected filters.")


# ---------------------------------------------------------
# Authentication result distribution
# ---------------------------------------------------------

st.markdown("### Authentication Activity Timeline")

if filtered_authentication:
    authentication_timeline = []

    for row in filtered_authentication:
        authentication_timeline.append(
            {
                "Timestamp": row["timestamp"],
                "Username": row["username"],
                "Method": row["method"],
                "Result": row["result"],
                "Source IP": row["source_ip"],
                "Session ID": row["session_id"],
            }
        )

    timeline_data = pd.DataFrame(authentication_timeline)

    timeline_data["Timestamp"] = pd.to_datetime(
        timeline_data["Timestamp"],
        errors="coerce",
    )

    timeline_data = timeline_data.dropna(subset=["Timestamp"])

    if not timeline_data.empty:
        timeline_height = max(
            300,
            min(
                500,
                220 + (timeline_data["Username"].nunique() * 45),
            ),
        )

        auth_timeline = (
            alt.Chart(timeline_data)
            .mark_circle(size=130)
            .encode(
                x=alt.X(
                    "Timestamp:T",
                    title="Authentication Time",
                    axis=alt.Axis(
                        format="%d %b %Y",
                        labelAngle=-35,
                    ),
                ),
                y=alt.Y(
                    "Username:N",
                    title="Username",
                    sort="-x",
                ),
                color=alt.Color(
                    "Result:N",
                    title="Result",
                ),
                tooltip=[
                    alt.Tooltip(
                        "Timestamp:T",
                        title="Timestamp",
                        format="%Y-%m-%d %H:%M:%S",
                    ),
                    alt.Tooltip(
                        "Username:N",
                        title="Username",
                    ),
                    alt.Tooltip(
                        "Method:N",
                        title="Method",
                    ),
                    alt.Tooltip(
                        "Result:N",
                        title="Result",
                    ),
                    alt.Tooltip(
                        "Source IP:N",
                        title="Source IP",
                    ),
                    alt.Tooltip(
                        "Session ID:N",
                        title="Session ID",
                    ),
                ],
            )
            .properties(
                height=timeline_height,
            )
            .interactive()
        )

        st.altair_chart(
            auth_timeline,
            use_container_width=True,
        )
    else:
        st.info("Authentication timestamps could not be parsed.")

else:
    st.info("No authentication data matches the selected filters.")


st.divider()


# Recent security alerts
# ---------------------------------------------------------

st.subheader("Recent Security Alerts")

if filtered_alerts:
    alert_display = []

    for row in filtered_alerts[:10]:
        alert_display.append(
            {
                "Severity": row["severity"],
                "Alert Type": row["alert_type"],
                "Source IP": row["source_ip"],
                "Session ID": row["session_id"],
                "Reason": row["reason"],
                "Timestamp": row["timestamp"],
            }
        )

    st.dataframe(
        alert_display,
        use_container_width=True,
        hide_index=True,
    )
else:
    st.success("No security alerts match the selected filters.")


# ---------------------------------------------------------
# Recent commands
# ---------------------------------------------------------

st.subheader("Recent Captured Commands")

if filtered_commands:
    command_display = []

    for row in filtered_commands[:15]:
        command_display.append(
            {
                "Command": row["command_text"],
                "Honeypot Response": row.get("response_text") or "",
                "Category": row["category"],
                "Source IP": row["source_ip"],
                "Session ID": row["session_id"],
                "Timestamp": row["timestamp"],
            }
        )

    st.dataframe(
        command_display,
        use_container_width=True,
        hide_index=True,
    )
else:
    st.info("No commands match the selected filters.")


# ---------------------------------------------------------
# Attack interaction
# ---------------------------------------------------------

st.subheader("Attack Interaction")

if filtered_commands:
    interaction_display = []

    # Build an alert lookup using session + command text.
    #
    # Alert evidence contains the command_text generated by the
    # detection engine. This lets the dashboard associate the
    # correct alert with the corresponding command.
    alert_lookup = {}

    for alert in filtered_alerts:
        try:
            import json

            evidence = json.loads(alert["evidence"])
            evidence_command = evidence.get("command_text")

            if evidence_command:
                key = (
                    alert["session_id"],
                    evidence_command,
                )

                # Keep the most recent matching alert.
                if key not in alert_lookup:
                    alert_lookup[key] = alert

        except (TypeError, ValueError, json.JSONDecodeError):
            continue

    for row in filtered_commands[:15]:
        key = (
            row["session_id"],
            row["command_text"],
        )

        alert = alert_lookup.get(key)

        interaction_display.append(
            {
                "Command": row["command_text"],
                "Honeypot Response": row.get("response_text") or "",
                "Category": row["category"],
                "Severity": alert["severity"] if alert else "NONE",
                "Alert Type": alert["alert_type"] if alert else "None",
                "Source IP": row["source_ip"],
                "Timestamp": row["timestamp"],
            }
        )

    st.dataframe(
        interaction_display,
        use_container_width=True,
        hide_index=True,
    )
else:
    st.info("No attack interactions match the selected filters.")


# ---------------------------------------------------------
# Authentication activity
# ---------------------------------------------------------

st.subheader("Authentication Activity")

if filtered_authentication:
    authentication_display = []

    for row in filtered_authentication[:15]:
        authentication_display.append(
            {
                "Username": row["username"],
                "Captured Password": row["password"],
                "Method": row["method"],
                "Result": row["result"],
                "Source IP": row["source_ip"],
                "Session ID": row["session_id"],
                "Timestamp": row["timestamp"],
            }
        )

    st.dataframe(
        authentication_display,
        use_container_width=True,
        hide_index=True,
    )
else:
    st.info("No authentication attempts match the selected filters.")


# ---------------------------------------------------------
# Session activity
# ---------------------------------------------------------

st.subheader("SSH Session Activity")

if filtered_sessions:
    session_display = []

    for row in filtered_sessions[:15]:
        session_display.append(
            {
                "Session ID": row["session_id"],
                "Source IP": row["source_ip"],
                "Source Port": row["source_port"],
                "Started": row["started_at"],
                "Ended": row["ended_at"],
                "Outcome": row["outcome"],
            }
        )

    st.dataframe(
        session_display,
        use_container_width=True,
        hide_index=True,
    )
else:
    st.info("No sessions match the selected filters.")


# ---------------------------------------------------------
# Database status
# ---------------------------------------------------------

st.divider()

st.success(
    f"Connected to live database: {DB_PATH} | "
    "Read-only monitoring mode"
)

st.caption(
    "SSH-HoneyGuard does not execute attacker commands. "
    "Commands are captured and classified by the honeypot detection engine."
)
