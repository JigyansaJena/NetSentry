
import os
import tempfile

import pandas as pd
import plotly.express as px
import streamlit as st

from analyzer import analyze_pcap
from detector import detect_port_scans


st.set_page_config(
    page_title="NetSentry | Threat Operations",
    page_icon="N",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------- Styling ----------
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

.stApp {
    background: #080c17;
    color: #e6edf8;
    font-family: 'Inter', sans-serif;
}
[data-testid="stHeader"] { background: transparent; }
[data-testid="stSidebar"] {
    background: #111a36;
    border-right: 1px solid #202b49;
}
[data-testid="stSidebar"] > div { padding-top: 1.2rem; }
.block-container {
    padding-top: 1.8rem;
    padding-bottom: 2rem;
    max-width: 1600px;
}
h1, h2, h3 { color: #eef3ff !important; letter-spacing: -0.5px; }
p, label { color: #a7b4cc; }
small { color: #8796b2; }

.brand {
    font-size: 1.35rem;
    font-weight: 700;
    letter-spacing: 1px;
    color: #f0f5ff;
}
.brand-sub {
    font-size: 0.72rem;
    color: #8292b0;
    margin-top: 3px;
}
.panel {
    background: #121a2b;
    border: 1px solid #202c43;
    border-radius: 12px;
    padding: 16px;
    margin-bottom: 14px;
}
.panel-title {
    color: #edf3ff;
    font-size: 0.98rem;
    font-weight: 600;
    margin-bottom: 4px;
}
.muted {
    color: #8796b2;
    font-size: 0.78rem;
}
.metric-card {
    background: #121a2b;
    border: 1px solid #202c43;
    border-radius: 10px;
    padding: 16px 14px;
    min-height: 94px;
}
.metric-label {
    color: #91a0ba;
    font-size: 0.78rem;
    margin-bottom: 8px;
}
.metric-value {
    color: #f0f5ff;
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.65rem;
    font-weight: 600;
}
.section-label {
    color: #6e86b4;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.72rem;
    letter-spacing: 1px;
    margin: 24px 0 12px;
}
div[data-testid="stDataFrame"] {
    border: 1px solid #202c43;
    border-radius: 9px;
}
.stButton button, .stDownloadButton button {
    border-radius: 7px;
    font-weight: 500;
}
div[data-baseweb="select"] > div,
div[data-baseweb="input"] > div {
    background: #0b1120;
    border-color: #293754;
}
hr { border-color: #202c43; }
</style>
""", unsafe_allow_html=True)


def metric_card(label, value):
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">{label}</div>
            <div class="metric-value">{value}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def section(label):
    st.markdown(
        f'<div class="section-label">{label}</div>',
        unsafe_allow_html=True,
    )


# ---------- Sidebar ----------
with st.sidebar:
    st.markdown(
        '<div class="brand">◈ NETSENTRY</div>'
        '<div class="brand-sub">NETWORK THREAT OPERATIONS</div>',
        unsafe_allow_html=True,
    )
    st.divider()

    page = st.radio(
        "NAVIGATION",
        [
            "Overview",
            "Filters",
            "Alerts",
            "Packets",
            "Traffic Graph",
        ],
        label_visibility="collapsed",
    )

    st.divider()
    st.markdown("**Capture source**")
    uploaded = st.file_uploader(
        "Upload PCAP",
        type=["pcap", "pcapng"],
        label_visibility="collapsed",
    )

    st.caption("Use captures you own or have permission to inspect.")
    st.divider()

    st.markdown("**Detection configuration**")
    window_seconds = st.slider("Time window (seconds)", 1, 60, 10)
    min_ports = st.slider("Unique-port threshold", 5, 50, 15)


# ---------- Header ----------
st.markdown(
    '<div style="font-size:1.55rem;font-weight:700">'
    'Network Investigation</div>'
    '<div style="color:#8998b2;font-size:.85rem;margin-top:5px">'
    'Inspect captured traffic, narrow packet activity and investigate '
    'potentially suspicious patterns.</div>',
    unsafe_allow_html=True,
)

section("01 / CAPTURE")

if uploaded is None:
    st.markdown(
        """
        <div class="panel">
            <div class="panel-title">No capture loaded</div>
            <p>Upload a PCAP or PCAPNG file from the sidebar to begin
            your investigation.</p>
            <p class="muted">The dashboard will use actual packet data.
            No sample alerts or fabricated statistics are shown.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.stop()


# ---------- Analyze uploaded file ----------
try:
    suffix = (
        ".pcapng"
        if uploaded.name.lower().endswith(".pcapng")
        else ".pcap"
    )
    temp_path = None

    with st.spinner("Reading and analyzing packets..."):
        try:
            with tempfile.NamedTemporaryFile(
                suffix=suffix, delete=False
            ) as temp:
                temp.write(uploaded.getvalue())
                temp_path = temp.name

            df = analyze_pcap(temp_path)
        finally:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)

    if df.empty:
        st.warning("No packets were found in this capture.")
        st.stop()

    alerts = detect_port_scans(
        df,
        window_seconds=window_seconds,
        min_unique_ports=min_ports,
    )

except Exception as exc:
    st.error(f"Could not analyze the capture: {exc}")
    st.stop()


# ---------- Filters ----------
section("02 / FILTER CONTROLS")

with st.container(border=True):
    st.markdown("**Filter Controls**")
    st.caption(f"Loaded file: {uploaded.name}")

    f1, f2 = st.columns(2)
    f3, f4 = st.columns(2)

    protocols = sorted(df["protocol"].dropna().unique())
    with f1:
        selected_protocol = st.selectbox(
            "Protocol",
            ["All Protocols"] + protocols,
        )

    with f2:
        source_query = st.text_input("Source IP contains", placeholder="e.g. 192.168.1.10")

    with f3:
        destination_query = st.text_input(
            "Destination IP contains", placeholder="e.g. 8.8.8.8"
        )

    with f4:
        risky_only = st.checkbox("Potentially flagged IPs only")

    # Use actual capture time range when available.
    valid_times = df["timestamp"].dropna()

    if not valid_times.empty:
        t1, t2 = st.columns(2)
        earliest = valid_times.min().date()
        latest = valid_times.max().date()

        with t1:
            start_date = st.date_input(
                "Start date", value=earliest,
                min_value=earliest, max_value=latest,
            )
        with t2:
            end_date = st.date_input(
                "End date", value=latest,
                min_value=earliest, max_value=latest,
            )
    else:
        start_date = end_date = None

    reset_col, note_col = st.columns([1, 4])
    with reset_col:
        reset = st.button("Reset filters", width='stretch')
    with note_col:
        st.caption("Filters apply to the packet table and summary metrics.")


# Reset button triggers a clean rerun so controls return to defaults.
if reset:
    st.rerun()

filtered = df.copy()

if selected_protocol != "All Protocols":
    filtered = filtered[filtered["protocol"] == selected_protocol]

if source_query.strip():
    filtered = filtered[
        filtered["src_ip"].fillna("").str.contains(
            source_query.strip(), case=False, regex=False
        )
    ]

if destination_query.strip():
    filtered = filtered[
        filtered["dst_ip"].fillna("").str.contains(
            destination_query.strip(), case=False, regex=False
        )
    ]

if start_date is not None and end_date is not None:
    if start_date > end_date:
        st.error("Start date must be on or before end date.")
        st.stop()

    filtered = filtered[
        filtered["timestamp"].dt.date.between(start_date, end_date)
    ]

# These IPs are associated with our port-scan rule, not confirmed attackers.
flagged_ips = set()
if not alerts.empty:
    flagged_ips.update(alerts["src_ip"].dropna().astype(str))
    flagged_ips.update(alerts["dst_ip"].dropna().astype(str))

if risky_only:
    filtered = filtered[
        filtered["src_ip"].astype(str).isin(flagged_ips)
        | filtered["dst_ip"].astype(str).isin(flagged_ips)
    ]


# ---------- Metrics ----------
section("03 / INVESTIGATION SUMMARY")

high_col, high_col2, high_col3, high_col4 = st.columns(4)

with high_col:
    metric_card("Filtered Packets", f"{len(filtered):,}")
with high_col2:
    metric_card("Port-Scan Alerts", f"{len(alerts):,}")
with high_col3:
    metric_card("Flagged IPs", f"{len(flagged_ips):,}")
with high_col4:
    metric_card(
        "Protocols Found",
        f"{filtered['protocol'].nunique() if not filtered.empty else 0:,}",
    )


# ---------- Overview ----------
if page in ["Overview", "Traffic Graph"]:
    section("04 / TRAFFIC PROFILE")

    if filtered.empty:
        st.info("No packets match the selected filters.")
    else:
        left, right = st.columns([1, 1.5])

        with left:
            st.markdown("**Protocol distribution**")
            counts = (
                filtered["protocol"].value_counts()
                .rename_axis("Protocol")
                .reset_index(name="Packets")
            )
            fig = px.pie(
                counts, names="Protocol", values="Packets", hole=0.6
            )
            fig.update_layout(
                paper_bgcolor="#121a2b",
                plot_bgcolor="#121a2b",
                font_color="#dce6f8",
                margin=dict(t=20, b=10, l=10, r=10),
                height=300,
                legend_title_text="",
            )
            st.plotly_chart(fig, width='stretch')

        with right:
            st.markdown("**Packets over time**")
            timeline = (
                filtered.dropna(subset=["timestamp"])
                .set_index("timestamp")
                .resample("1s")
                .size()
                .rename("Packets")
                .reset_index()
            )
            fig = px.line(
                timeline, x="timestamp", y="Packets",
                labels={"timestamp": "Time", "Packets": "Packets / second"},
            )
            fig.update_traces(line_color="#438bff", line_width=2)
            fig.update_layout(
                paper_bgcolor="#121a2b",
                plot_bgcolor="#121a2b",
                font_color="#dce6f8",
                margin=dict(t=20, b=10, l=10, r=10),
                height=300,
                xaxis=dict(showgrid=False),
                yaxis=dict(gridcolor="#26324a"),
            )
            st.plotly_chart(fig, width='stretch')


# ---------- Alerts ----------
if page in ["Overview", "Alerts"]:
    section("05 / DETECTION ALERTS")

    if alerts.empty:
        st.success("No port-scan patterns crossed the configured threshold.")
        st.caption(
            "This does not mean the capture is safe. Only the current "
            "port-scan heuristic was evaluated."
        )
    else:
        st.warning(
            f"{len(alerts)} possible port-scan pattern(s) detected. "
            "These are indicators for review, not confirmed attacks."
        )
        st.dataframe(alerts, width='stretch', hide_index=True)

        st.download_button(
            "Export alerts CSV",
            alerts.to_csv(index=False).encode("utf-8"),
            file_name="netsentry_alerts.csv",
            mime="text/csv",
        )


# ---------- Packet table ----------
if page in ["Overview", "Filters", "Packets"]:
    section("06 / PACKET INVESTIGATION TABLE")

    st.caption(f"Displaying {len(filtered):,} packet(s)")

    display_df = filtered.copy()
    display_df["timestamp"] = display_df["timestamp"].astype(str)

    st.dataframe(
        display_df,
        width='stretch',
        hide_index=True,
        height=420,
    )

    st.download_button(
        "Export filtered packet data CSV",
        filtered.to_csv(index=False).encode("utf-8"),
        file_name="netsentry_filtered_packets.csv",
        mime="text/csv",
    )

st.divider()
st.caption(
    "NETSENTRY · Network traffic research prototype · "
    "Heuristic alerts require human investigation."
)
