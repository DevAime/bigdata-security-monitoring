import pandas as pd

WORKING_HOURS_START = 8   # 8 AM
WORKING_HOURS_END = 18    # 6 PM
MAX_REQUESTS_PER_WINDOW = 10  # max actions per user per hour
LONG_DURATION_THRESHOLD = 400
SHORT_DURATION_THRESHOLD = 1
SUSPICIOUS_LOCATIONS = ["Unknown", "Foreign"]
HIGH_RISK_ACTIONS = ["delete"]
HIGH_RISK_ROLES_FOR_DELETE = ["guest", "analyst"]


def load_and_prepare(filepath):
    df = pd.read_csv(filepath, parse_dates=["timestamp"])
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"])
    df["hour"] = df["timestamp"].dt.hour
    df["date"] = df["timestamp"].dt.date
    df["flags"] = ""
    return df


def flag_outside_hours(df):
    mask = (df["hour"] < WORKING_HOURS_START) | (df["hour"] >= WORKING_HOURS_END)
    df.loc[mask, "flags"] += "outside_working_hours; "
    return df


def flag_unknown_location(df):
    mask = df["location"].isin(SUSPICIOUS_LOCATIONS)
    df.loc[mask, "flags"] += "suspicious_location; "
    return df


def flag_unknown_device(df):
    mask = df["device_type"].str.lower() == "unknown"
    df.loc[mask, "flags"] += "unknown_device; "
    return df


def flag_access_duration(df):
    long_mask = df["access_duration"] > LONG_DURATION_THRESHOLD
    short_mask = df["access_duration"] <= SHORT_DURATION_THRESHOLD
    df.loc[long_mask, "flags"] += "unusually_long_session; "
    df.loc[short_mask, "flags"] += "unusually_short_session; "
    return df


def flag_high_frequency(df):
    # Count actions per user per hour window
    df["hour_window"] = df["timestamp"].dt.floor("H")
    freq = (
        df.groupby(["user_id", "hour_window"])
        .size()
        .reset_index(name="request_count")
    )
    freq["high_frequency"] = freq["request_count"] > MAX_REQUESTS_PER_WINDOW
    df = df.merge(freq[["user_id", "hour_window", "request_count", "high_frequency"]],
                  on=["user_id", "hour_window"], how="left")
    df.loc[df["high_frequency"] == True, "flags"] += "high_frequency_access; "
    return df


def flag_unauthorized_delete(df):
    mask = (df["action"] == "delete") & (df["role"].isin(HIGH_RISK_ROLES_FOR_DELETE))
    df.loc[mask, "flags"] += "unauthorized_delete_attempt; "
    return df


def flag_failed_access(df):
    mask = df["status"] == "failure"
    df.loc[mask, "flags"] += "failed_access; "
    return df


def flag_multiple_locations(df):
    # If a user appears from more than 2 distinct locations in a single day, flag all their records that day
    loc_count = (
        df.groupby(["user_id", "date"])["location"]
        .nunique()
        .reset_index(name="location_count")
    )
    loc_count["multi_location"] = loc_count["location_count"] > 2
    df = df.merge(loc_count[["user_id", "date", "multi_location"]], on=["user_id", "date"], how="left")
    df.loc[df["multi_location"] == True, "flags"] += "multiple_locations_same_day; "
    return df


def apply_all_rules(df):
    df = flag_outside_hours(df)
    df = flag_unknown_location(df)
    df = flag_unknown_device(df)
    df = flag_access_duration(df)
    df = flag_high_frequency(df)
    df = flag_unauthorized_delete(df)
    df = flag_failed_access(df)
    df = flag_multiple_locations(df)
    df["is_suspicious"] = df["flags"].str.strip() != ""
    df["flag_count"] = df["flags"].apply(lambda x: len([f for f in x.split(";") if f.strip()]))
    return df


def get_suspicious_only(df):
    return df[df["is_suspicious"]].copy()


def summary_stats(df):
    total = len(df)
    suspicious = df["is_suspicious"].sum()
    return {
        "total_records": total,
        "suspicious_records": int(suspicious),
        "clean_records": int(total - suspicious),
        "suspicion_rate": round((suspicious / total) * 100, 2) if total > 0 else 0,
    }