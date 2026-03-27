import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from rules import load_and_prepare, apply_all_rules, get_suspicious_only, summary_stats

st.set_page_config(page_title="Big Data Security Monitor", layout="wide")

# ── Sidebar Navigation ──────────────────────────────────────────────────────

st.sidebar.title("Navigation")
page = st.sidebar.radio(
    "Go to",
    ["Upload Logs", "Analysis Dashboard", "Security Monitoring", "Rule Reference"]
)

# ── Session State ────────────────────────────────────────────────────────────

if "df_raw" not in st.session_state:
    st.session_state.df_raw = None
if "df_analyzed" not in st.session_state:
    st.session_state.df_analyzed = None

# ── Page: Upload Logs ────────────────────────────────────────────────────────

if page == "Upload Logs":
    st.title("Upload Access Logs")
    st.write(
        "Upload your CSV file containing the simulated access logs. "
        "The file must contain a 'timestamp' column with full datetime values."
    )

    uploaded_file = st.file_uploader("Choose a CSV file", type=["csv"])

    if uploaded_file is not None:
        try:
            df = load_and_prepare(uploaded_file)
            df = apply_all_rules(df)
            st.session_state.df_raw = df
            st.session_state.df_analyzed = df

            st.success("File loaded and processed successfully.")
            st.subheader("Preview (first 20 rows)")
            st.dataframe(df.head(20))

            stats = summary_stats(df)
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Total Records", stats["total_records"])
            col2.metric("Suspicious Records", stats["suspicious_records"])
            col3.metric("Clean Records", stats["clean_records"])
            col4.metric("Suspicion Rate", f"{stats['suspicion_rate']}%")

        except Exception as e:
            st.error(f"Failed to load file: {e}")
    else:
        st.info("No file uploaded yet. Please upload a CSV to continue.")

# ── Page: Analysis Dashboard ─────────────────────────────────────────────────

elif page == "Analysis Dashboard":
    st.title("Analysis Dashboard")

    if st.session_state.df_analyzed is None:
        st.warning("No data loaded. Please go to 'Upload Logs' first.")
    else:
        df = st.session_state.df_analyzed

        st.subheader("Filters")
        col_f1, col_f2, col_f3 = st.columns(3)
        with col_f1:
            selected_roles = st.multiselect(
                "Filter by Role", options=df["role"].unique().tolist(),
                default=df["role"].unique().tolist()
            )
        with col_f2:
            selected_actions = st.multiselect(
                "Filter by Action", options=df["action"].unique().tolist(),
                default=df["action"].unique().tolist()
            )
        with col_f3:
            selected_datasets = st.multiselect(
                "Filter by Dataset", options=df["dataset_name"].unique().tolist(),
                default=df["dataset_name"].unique().tolist()
            )

        df_filtered = df[
            df["role"].isin(selected_roles) &
            df["action"].isin(selected_actions) &
            df["dataset_name"].isin(selected_datasets)
        ]

        st.markdown("---")

        # ── Chart 1: Actions over time ──────────────────────────────────────
        st.subheader("Access Activity Over Time")
        activity_by_hour = df_filtered.groupby(
            df_filtered["timestamp"].dt.floor("H")
        ).size().reset_index(name="count")
        activity_by_hour.columns = ["hour", "count"]

        fig1, ax1 = plt.subplots(figsize=(12, 4))
        ax1.plot(activity_by_hour["hour"], activity_by_hour["count"], color="#2563eb", linewidth=2)
        ax1.set_xlabel("Time")
        ax1.set_ylabel("Number of Actions")
        ax1.set_title("Access Events per Hour")
        ax1.xaxis.set_major_formatter(mdates.DateFormatter("%m/%d %H:%M"))
        plt.xticks(rotation=45)
        plt.tight_layout()
        st.pyplot(fig1)

        # ── Chart 2: Actions by type ────────────────────────────────────────
        st.subheader("Action Type Distribution")
        action_counts = df_filtered["action"].value_counts()

        fig2, ax2 = plt.subplots(figsize=(5, 4))
        colors = ["#2563eb", "#dc2626", "#16a34a"]
        ax2.bar(action_counts.index, action_counts.values, color=colors[:len(action_counts)])
        ax2.set_xlabel("Action")
        ax2.set_ylabel("Count")
        ax2.set_title("Distribution of Actions")
        plt.tight_layout()
        st.pyplot(fig2)

        # ── Chart 3: Top users by access count ─────────────────────────────
        st.subheader("Most Active Users")
        user_counts = df_filtered["user_id"].value_counts().head(10)

        fig3, ax3 = plt.subplots(figsize=(8, 4))
        ax3.barh(user_counts.index[::-1], user_counts.values[::-1], color="#7c3aed")
        ax3.set_xlabel("Number of Accesses")
        ax3.set_title("Top 10 Users by Access Count")
        plt.tight_layout()
        st.pyplot(fig3)

        # ── Chart 4: Access by hour of day ──────────────────────────────────
        st.subheader("Access by Hour of Day")
        hour_dist = df_filtered["hour"].value_counts().sort_index()

        fig4, ax4 = plt.subplots(figsize=(10, 4))
        bar_colors = [
            "#dc2626" if (h < 8 or h >= 18) else "#2563eb"
            for h in hour_dist.index
        ]
        ax4.bar(hour_dist.index, hour_dist.values, color=bar_colors)
        ax4.set_xlabel("Hour of Day (0-23)")
        ax4.set_ylabel("Access Count")
        ax4.set_title("Access Frequency by Hour (red = outside working hours)")
        ax4.set_xticks(range(0, 24))
        plt.tight_layout()
        st.pyplot(fig4)

        # ── Chart 5: Location distribution ──────────────────────────────────
        st.subheader("Access by Location")
        loc_counts = df_filtered["location"].value_counts()

        fig5, ax5 = plt.subplots(figsize=(7, 4))
        loc_colors = [
            "#dc2626" if loc in ["Unknown", "Foreign"] else "#2563eb"
            for loc in loc_counts.index
        ]
        ax5.bar(loc_counts.index, loc_counts.values, color=loc_colors)
        ax5.set_xlabel("Location")
        ax5.set_ylabel("Count")
        ax5.set_title("Access by Location (red = suspicious)")
        plt.xticks(rotation=45)
        plt.tight_layout()
        st.pyplot(fig5)

        # ── Chart 6: Access duration distribution ───────────────────────────
        st.subheader("Session Duration Distribution")
        fig6, ax6 = plt.subplots(figsize=(8, 4))
        ax6.hist(df_filtered["access_duration"], bins=30, color="#0891b2", edgecolor="white")
        ax6.axvline(x=400, color="#dc2626", linestyle="--", label="Long threshold (400s)")
        ax6.axvline(x=1, color="#f97316", linestyle="--", label="Short threshold (1s)")
        ax6.set_xlabel("Session Duration (seconds)")
        ax6.set_ylabel("Count")
        ax6.set_title("Distribution of Session Durations")
        ax6.legend()
        plt.tight_layout()
        st.pyplot(fig6)

        # ── Chart 7: Role breakdown ──────────────────────────────────────────
        st.subheader("Access by Role")
        role_counts = df_filtered["role"].value_counts()

        fig7, ax7 = plt.subplots(figsize=(5, 5))
        ax7.pie(
            role_counts.values,
            labels=role_counts.index,
            autopct="%1.1f%%",
            colors=["#2563eb", "#dc2626", "#16a34a"]
        )
        ax7.set_title("Role Distribution")
        plt.tight_layout()
        st.pyplot(fig7)

        # ── Raw data table ───────────────────────────────────────────────────
        st.subheader("Filtered Data Table")
        st.dataframe(df_filtered[[
            "user_id", "role", "timestamp", "action",
            "dataset_name", "location", "status", "device_type", "access_duration"
        ]])

# ── Page: Security Monitoring ─────────────────────────────────────────────────

elif page == "Security Monitoring":
    st.title("Security Monitoring")

    if st.session_state.df_analyzed is None:
        st.warning("No data loaded. Please go to 'Upload Logs' first.")
    else:
        df = st.session_state.df_analyzed
        stats = summary_stats(df)

        # ── Summary metrics ──────────────────────────────────────────────────
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Records", stats["total_records"])
        col2.metric("Flagged Records", stats["suspicious_records"])
        col3.metric("Clean Records", stats["clean_records"])
        col4.metric("Suspicion Rate", f"{stats['suspicion_rate']}%")

        st.markdown("---")

        # ── Flag breakdown ───────────────────────────────────────────────────
        st.subheader("Breakdown of Triggered Rules")

        rule_labels = {
            "outside_working_hours": "Outside Working Hours",
            "suspicious_location": "Suspicious Location",
            "unknown_device": "Unknown Device Type",
            "unusually_long_session": "Unusually Long Session (>400s)",
            "unusually_short_session": "Unusually Short Session (<=1s)",
            "high_frequency_access": "High Frequency Access",
            "unauthorized_delete_attempt": "Unauthorized Delete (guest/analyst)",
            "failed_access": "Failed Access Attempt",
            "multiple_locations_same_day": "Multiple Locations Same Day",
        }

        flag_counts = {}
        for key, label in rule_labels.items():
            count = df["flags"].str.contains(key, na=False).sum()
            flag_counts[label] = count

        flag_df = pd.DataFrame(list(flag_counts.items()), columns=["Rule", "Count"])
        flag_df = flag_df.sort_values("Count", ascending=False)

        fig_flags, ax_flags = plt.subplots(figsize=(10, 5))
        ax_flags.barh(flag_flags := flag_df["Rule"][::-1], flag_df["Count"][::-1], color="#dc2626")
        ax_flags.set_xlabel("Number of Records Flagged")
        ax_flags.set_title("Flagged Records per Rule")
        plt.tight_layout()
        st.pyplot(fig_flags)

        st.dataframe(flag_df)

        st.markdown("---")

        # ── High risk users ──────────────────────────────────────────────────
        st.subheader("Highest Risk Users")
        suspicious_df = get_suspicious_only(df)
        risk_by_user = (
            suspicious_df.groupby("user_id")["flag_count"]
            .sum()
            .reset_index()
            .sort_values("flag_count", ascending=False)
            .head(10)
        )

        fig_risk, ax_risk = plt.subplots(figsize=(8, 4))
        ax_risk.barh(risk_by_user["user_id"][::-1], risk_by_user["flag_count"][::-1], color="#7c3aed")
        ax_risk.set_xlabel("Total Flag Count")
        ax_risk.set_title("Top 10 Users by Total Flags")
        plt.tight_layout()
        st.pyplot(fig_risk)

        st.markdown("---")

        # ── Filter suspicious records ────────────────────────────────────────
        st.subheader("Suspicious Records Explorer")

        available_rules = list(rule_labels.keys())
        selected_rule = st.selectbox(
            "Filter by specific rule (or see all suspicious)",
            options=["All Suspicious"] + [rule_labels[r] for r in available_rules]
        )

        if selected_rule == "All Suspicious":
            display_df = suspicious_df
        else:
            rule_key = [k for k, v in rule_labels.items() if v == selected_rule][0]
            display_df = df[df["flags"].str.contains(rule_key, na=False)]

        st.write(f"Showing {len(display_df)} records")
        st.dataframe(display_df[[
            "user_id", "role", "timestamp", "action", "dataset_name",
            "location", "status", "device_type", "access_duration", "flags"
        ]])

        # ── Download flagged records ─────────────────────────────────────────
        csv_export = suspicious_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="Download All Suspicious Records as CSV",
            data=csv_export,
            file_name="suspicious_logs.csv",
            mime="text/csv"
        )

# ── Page: Rule Reference ──────────────────────────────────────────────────────

elif page == "Rule Reference":
    st.title("Monitoring Rule Reference")
    st.write(
        "This page documents all detection rules applied by the monitoring system. "
        "Each rule targets a specific type of suspicious behavior observed in access logs."
    )

    rules = [
        {
            "Rule": "Outside Working Hours",
            "Condition": "Access timestamp before 08:00 or after 18:00",
            "Rationale": "Legitimate users typically operate during business hours. Access at odd hours may indicate unauthorized or automated activity.",
            "Flag": "outside_working_hours",
        },
        {
            "Rule": "Suspicious Location",
            "Condition": "Location is 'Unknown' or 'Foreign'",
            "Rationale": "Unknown locations may mean the system could not identify the source. Foreign access may be outside expected user geography.",
            "Flag": "suspicious_location",
        },
        {
            "Rule": "Unknown Device",
            "Condition": "device_type is 'unknown'",
            "Rationale": "An unidentified device type can indicate an attempt to hide the access origin or use of an unauthorized endpoint.",
            "Flag": "unknown_device",
        },
        {
            "Rule": "Unusually Long Session",
            "Condition": "access_duration > 400 seconds",
            "Rationale": "Very long sessions may indicate data exfiltration, bulk downloading, or a session that was left open and compromised.",
            "Flag": "unusually_long_session",
        },
        {
            "Rule": "Unusually Short Session",
            "Condition": "access_duration <= 1 second",
            "Rationale": "Sessions of 1 second or less are unlikely to represent genuine user activity and may be automated probing or script-driven access.",
            "Flag": "unusually_short_session",
        },
        {
            "Rule": "High Frequency Access",
            "Condition": "User performs more than 10 actions within a single hour",
            "Rationale": "A high volume of requests in a short time may indicate a brute-force attempt, automated scraping, or an insider threat.",
            "Flag": "high_frequency_access",
        },
        {
            "Rule": "Unauthorized Delete",
            "Condition": "action is 'delete' and role is 'guest' or 'analyst'",
            "Rationale": "Delete operations should be restricted to administrators. Deletion by lower-privilege roles is a policy violation.",
            "Flag": "unauthorized_delete_attempt",
        },
        {
            "Rule": "Failed Access Attempt",
            "Condition": "status is 'failure'",
            "Rationale": "Failed access can indicate credential stuffing, brute force attacks, or a misconfigured application attempting unauthorized access.",
            "Flag": "failed_access",
        },
        {
            "Rule": "Multiple Locations Same Day",
            "Condition": "User appears from more than 2 distinct locations in a single calendar day",
            "Rationale": "A user physically cannot be in many locations simultaneously. This pattern may indicate credential sharing or account compromise.",
            "Flag": "multiple_locations_same_day",
        },
    ]

    for rule in rules:
        with st.expander(rule["Rule"]):
            st.write(f"**Condition:** {rule['Condition']}")
            st.write(f"**Rationale:** {rule['Rationale']}")
            st.code(rule["Flag"], language="text")


