import streamlit as st
import pandas as pd

st.set_page_config(page_title="CyberShield | Security Dashboard", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
[data-testid="stMetric"] {
    background-color: #1b2230;
    padding: 18px;
    border-radius: 12px;
    border: 1px solid #303846;
}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ CyberShield")
st.subheader("Cybersecurity Login Activity Monitoring Dashboard")
st.caption("Explore login records, flag repeated failed-login patterns, and export reports.")

SAMPLE_DATA = pd.DataFrame({
    "timestamp": [
        "2026-10-20 08:15:00", "2026-10-20 08:17:00", "2026-10-20 08:20:00",
        "2026-10-20 09:10:00", "2026-10-20 09:12:00", "2026-10-20 09:15:00",
        "2026-10-20 10:30:00", "2026-10-20 10:32:00", "2026-10-20 11:45:00",
        "2026-10-20 11:47:00", "2026-10-20 12:00:00", "2026-10-20 12:05:00"
    ],
    "username": ["admin", "admin", "admin", "john", "john", "john",
                 "alice", "alice", "guest", "guest", "root", "alice"],
    "ip_address": ["192.168.1.10", "192.168.1.10", "192.168.1.10",
                   "192.168.1.20", "192.168.1.20", "192.168.1.20",
                   "10.0.0.5", "10.0.0.5", "203.0.113.45", "203.0.113.45",
                   "198.51.100.22", "10.0.0.5"],
    "status": ["Success", "Failed", "Failed", "Success", "Failed", "Failed",
               "Success", "Success", "Failed", "Failed", "Failed", "Success"]
})

st.sidebar.header("⚙️ Dashboard Settings")
uploaded = st.sidebar.file_uploader("Upload login records (CSV)", type=["csv"])
if uploaded is not None:
    try:
        data = pd.read_csv(uploaded)
    except Exception as exc:
        st.error(f"Could not read the CSV: {exc}")
        st.stop()
else:
    data = SAMPLE_DATA.copy()
    st.sidebar.info("Using synthetic demonstration data, not live monitoring.")

data.columns = [str(c).strip().lower().replace(" ", "_") for c in data.columns]
required = {"timestamp", "username", "ip_address", "status"}
missing = required - set(data.columns)
if missing:
    st.error("Missing required CSV columns: " + ", ".join(sorted(missing)))
    st.info("Required columns: timestamp, username, ip_address, status")
    st.stop()

df = data.copy()
df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
df["username"] = df["username"].fillna("Unknown").astype(str).str.strip()
df["ip_address"] = df["ip_address"].fillna("").astype(str).str.strip()
df["status"] = df["status"].fillna("").astype(str).str.strip()
df = df.dropna(subset=["timestamp"])
df = df[df["ip_address"] != ""].copy()
if df.empty:
    st.warning("No valid login records are available.")
    st.stop()

status_map = {
    "success": "Success", "successful": "Success", "login_success": "Success",
    "failed": "Failed", "failure": "Failed", "login_failed": "Failed"
}
df["status"] = df["status"].apply(lambda x: status_map.get(x.lower(), x))

unknown_statuses = sorted(set(df["status"]) - {"Success", "Failed"})
if unknown_statuses:
    st.warning("Unrecognized status labels (not counted as success/failure): "
               + ", ".join(unknown_statuses))

threshold = st.sidebar.slider("Failed attempts per IP to flag", 2, 10, 3)
min_date = df["timestamp"].dt.date.min()
max_date = df["timestamp"].dt.date.max()
date_choice = st.sidebar.date_input("Date range", value=(min_date, max_date),
                                    min_value=min_date, max_value=max_date)
if isinstance(date_choice, (tuple, list)):
    if len(date_choice) == 2:
        date_start, date_end = date_choice
    elif len(date_choice) == 1:
        date_start = date_end = date_choice[0]
    else:
        date_start, date_end = min_date, max_date
else:
    date_start = date_end = date_choice

date_df = df[(df["timestamp"].dt.date >= date_start) &
             (df["timestamp"].dt.date <= date_end)].copy()

# Detect from all records in the chosen date range, before display-status filtering.
failed_by_ip = (date_df[date_df["status"] == "Failed"]
                .groupby("ip_address").size()
                .rename("failed_attempts").reset_index())
suspicious = failed_by_ip[failed_by_ip["failed_attempts"] >= threshold] \
    .sort_values("failed_attempts", ascending=False)
suspicious_set = set(suspicious["ip_address"])

statuses = sorted(date_df["status"].unique().tolist())
selected_statuses = st.sidebar.multiselect("Statuses to display", statuses, default=statuses)
view = date_df[date_df["status"].isin(selected_statuses)].copy()
view["risk_flag"] = view["ip_address"].map(
    lambda ip: "Suspicious" if ip in suspicious_set else "Normal"
)

c1, c2, c3, c4 = st.columns(4)
c1.metric("Displayed Attempts", len(view))
c2.metric("Successful Logins", int((view["status"] == "Success").sum()))
c3.metric("Failed Logins", int((view["status"] == "Failed").sum()))
c4.metric("Suspicious IPs", len(suspicious_set))

st.divider()
left, right = st.columns(2)
with left:
    st.subheader("📊 Login Status Distribution")
    counts = view["status"].value_counts()
    if counts.empty:
        st.info("No records match the selected filters.")
    else:
        st.bar_chart(counts)
with right:
    st.subheader("🌐 Top IP Addresses")
    counts = view["ip_address"].value_counts().head(10)
    if counts.empty:
        st.info("No IP addresses to display.")
    else:
        st.bar_chart(counts)

st.subheader("🕒 Login Activity Over Time")
if view.empty:
    st.info("No login activity matches the selected filters.")
else:
    timeline = view.assign(hour=view["timestamp"].dt.floor("h")).groupby("hour").size()
    st.line_chart(timeline.rename("Attempts"))

st.divider()
st.subheader("🚨 Suspicious IP Detection")
st.caption(f"An IP is flagged at {threshold} or more failed attempts within the selected date range. This is a basic rule, not proof of malicious activity.")
if suspicious.empty:
    st.success("No IP addresses reached the configured threshold.")
else:
    st.dataframe(suspicious, use_container_width=True, hide_index=True)

st.divider()
st.subheader("📋 Login Records")
query = st.text_input("Search by IP address or username").strip().lower()
shown = view.copy()
if query:
    ip_mask = shown["ip_address"].str.lower().str.contains(query, na=False, regex=False)
    user_mask = shown["username"].str.lower().str.contains(query, na=False, regex=False)
    shown = shown[ip_mask | user_mask]

st.dataframe(shown.sort_values("timestamp", ascending=False), use_container_width=True, hide_index=True)
st.download_button("⬇️ Download Filtered Report (CSV)",
                   data=shown.to_csv(index=False).encode("utf-8"),
                   file_name="cybershield_login_report.csv", mime="text/csv")

st.caption("CyberShield is an educational dashboard for uploaded or demonstration records. It does not monitor a live network.")
