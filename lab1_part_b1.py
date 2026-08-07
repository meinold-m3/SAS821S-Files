"""
SAS821S Lab 1 — Part B1: Reproducible Data Preparation
Loads all evidence files, converts timestamps, reports data-quality
summary statistics and builds derived variables for the investigation.
"""

import pandas as pd
pd.set_option("display.width", 160)

DATA_PATH = r"C:\Users\kali hunter\Downloads\SAS\Lab1"  # path to evidence files (working copies only)

# --- Load with parsed timestamps ---
asset = pd.read_csv(f"{DATA_PATH}/ot_asset_inventory.csv")
user  = pd.read_csv(f"{DATA_PATH}/ot_user_directory.csv")
auth  = pd.read_csv(f"{DATA_PATH}/ot_authentication_logs.csv", parse_dates=["timestamp"])
dns   = pd.read_csv(f"{DATA_PATH}/ot_dns_logs.csv", parse_dates=["timestamp"])
fw    = pd.read_csv(f"{DATA_PATH}/ot_firewall_logs.csv", parse_dates=["timestamp"])
train = pd.read_csv(f"{DATA_PATH}/ot_network_flow_training.csv", parse_dates=["timestamp"])
inv   = pd.read_csv(f"{DATA_PATH}/ot_network_flow_investigation.csv", parse_dates=["timestamp"])

# --- Row counts / dtypes / missing / duplicates ---
print("ROW COUNTS")
for name, df in [("asset", asset), ("user", user), ("auth", auth), ("dns", dns),
                  ("firewall", fw), ("flow_train", train), ("flow_investigation", inv)]:
    print(f"  {name}: {len(df)} rows, {df.shape[1]} cols, "
          f"{df.isna().sum().sum()} missing cells, {df.duplicated().sum()} dup rows")

# --- Derived variables ---

# 1. hour, is_weekend, off_hours for auth/dns/fw
#    (flow files already ship with hour/is_weekend from the data provider)
for df in (auth, dns, fw):
    df["hour"] = df["timestamp"].dt.hour
    df["is_weekend"] = df["timestamp"].dt.dayofweek >= 5   # Sat=5, Sun=6
    # operational assumption per brief: normal office hours 06:00-20:00
    df["off_hours"] = ~df["hour"].between(6, 19)

# apply off_hours consistently to the flow data too
for df in (train, inv):
    df["off_hours"] = ~df["hour"].between(6, 19)

# 2. total_bytes and bytes_ratio for firewall logs
fw["total_bytes"] = fw["bytes_out"] + fw["bytes_in"]
fw["bytes_ratio"] = fw["bytes_out"] / fw["bytes_in"].replace(0, pd.NA)

# 3. total_bytes for flow data (src_bytes + dst_bytes)
for df in (train, inv):
    df["total_bytes"] = df["src_bytes"] + df["dst_bytes"]

# --- Verification ---
print("\nSample derived firewall row:")
print(fw[["event_id", "timestamp", "hour", "is_weekend", "off_hours",
           "bytes_out", "bytes_in", "total_bytes", "bytes_ratio"]].head(3))

print("\nSample derived auth row:")
print(auth[["event_id", "timestamp", "hour", "is_weekend", "off_hours",
             "user_id", "result"]].head(3))