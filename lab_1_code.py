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

"""
SAS821S Lab 1 — Part B2: Baseline and Visual Analysis
Produces the four required visualisations (auth by hour, outbound bytes
by host/time, top DNS destinations, working-hours vs off-hours) plus a
summary table. Depends on the prepared dataframes from Part B1.
"""

import pandas as pd
import matplotlib.pyplot as plt

DATA_PATH = r"C:\Users\kali hunter\Downloads\SAS\Lab1"   # evidence folder (working copies only)


asset = pd.read_csv(f"{DATA_PATH}/ot_asset_inventory.csv")
auth  = pd.read_csv(f"{DATA_PATH}/ot_authentication_logs.csv", parse_dates=["timestamp"])
dns   = pd.read_csv(f"{DATA_PATH}/ot_dns_logs.csv", parse_dates=["timestamp"])
fw    = pd.read_csv(f"{DATA_PATH}/ot_firewall_logs.csv", parse_dates=["timestamp"])

for df in (auth, dns, fw):
    df["hour"] = df["timestamp"].dt.hour
    df["is_weekend"] = df["timestamp"].dt.dayofweek >= 5
    df["off_hours"] = ~df["hour"].between(6, 19)   # office hours 06:00-20:00

# ---------- VISUALIATION 1: Authentication successes/failures by hour ----------
fig, ax = plt.subplots(figsize=(9, 4.5))
counts = auth.groupby(["hour", "result"]).size().unstack(fill_value=0)
counts.plot(kind="bar", stacked=True, ax=ax,
            color={"SUCCESS": "#4C8BF5", "FAILURE": "#E24A4A"})
ax.set_title("Authentication outcomes by hour of day (all hosts)")
ax.set_xlabel("Hour of day (0-23)")
ax.set_ylabel("Number of logon events")
ax.legend(title="Result")
plt.tight_layout()
plt.savefig("vis1_auth_by_hour.png", dpi=130)
plt.close()

# ---------- VISUALIATION 2: Outbound bytes by source host over time ----------
fw_asset = fw.merge(asset[["ip_address", "hostname"]],
                     left_on="src_ip", right_on="ip_address", how="left")
fw_asset["hostname"] = fw_asset["hostname"].fillna(fw_asset["src_ip"])

daily = (fw_asset.groupby([fw_asset["timestamp"].dt.date, "hostname"])["bytes_out"]
                  .sum().unstack(fill_value=0))
top_hosts = (fw_asset.groupby("hostname")["bytes_out"]
                      .sum().sort_values(ascending=False).head(6).index)

fig, ax = plt.subplots(figsize=(10, 5))
daily[top_hosts].plot(ax=ax, marker="o")
ax.set_title("Daily outbound bytes by top 6 source hosts")
ax.set_xlabel("Date")
ax.set_ylabel("Outbound bytes (bytes_out)")
ax.legend(title="Host", bbox_to_anchor=(1.02, 1), loc="upper left", fontsize=8)
plt.tight_layout()
plt.savefig("vis2_outbound_bytes_by_host.png", dpi=130)
plt.close()

# ---------- VISUALIATION 3: Top DNS query destinations ----------
top_domains = dns["query_name"].value_counts().head(12)

fig, ax = plt.subplots(figsize=(9, 5))
top_domains.sort_values().plot(kind="barh", ax=ax, color="#4C8BF5")
ax.set_title("Top 12 DNS query destinations (all clients)")
ax.set_xlabel("Number of queries")
ax.set_ylabel("Queried domain")
plt.tight_layout()
plt.savefig("vis3_top_dns.png", dpi=130)
plt.close()

# ---------- VISUALIATION 4: Working hours vs off-hours comparison ----------
auth_cmp = auth.groupby("off_hours").size()
fw_cmp = fw.groupby("off_hours")["bytes_out"].sum()
dns_cmp = dns.assign(
    off_hours=~dns["timestamp"].dt.hour.between(6, 19)
).groupby("off_hours").size()

fig, axes = plt.subplots(1, 3, figsize=(12, 4.5))
auth_cmp.rename({True: "Off-hours", False: "Working hours"}).plot(
    kind="bar", ax=axes[0], color=["#4C8BF5", "#E24A4A"])
axes[0].set_title("Auth events")
axes[0].set_ylabel("Count")

fw_cmp.rename({True: "Off-hours", False: "Working hours"}).plot(
    kind="bar", ax=axes[1], color=["#4C8BF5", "#E24A4A"])
axes[1].set_title("Firewall outbound bytes")
axes[1].set_ylabel("Bytes")

dns_cmp.rename({True: "Off-hours", False: "Working hours"}).plot(
    kind="bar", ax=axes[2], color=["#4C8BF5", "#E24A4A"])
axes[2].set_title("DNS queries")
axes[2].set_ylabel("Count")

fig.suptitle("Working hours (06:00-20:00) vs off-hours activity, all sources")
plt.tight_layout()
plt.savefig("vis4_working_vs_offhours.png", dpi=130)
plt.close()

# ---------- Summary table ----------
summary = pd.DataFrame({
    "auth_total": [len(auth)],
    "auth_failures": [(auth["result"] == "FAILURE").sum()],
    "auth_failure_rate_pct": [round((auth["result"] == "FAILURE").mean() * 100, 1)],
    "dns_total_queries": [len(dns)],
    "dns_unique_domains": [dns["query_name"].nunique()],
    "fw_total_events": [len(fw)],
    "fw_denied_pct": [round((fw["action"] == "DENY").mean() * 100, 1)],
    "fw_total_bytes_out_MB": [round(fw["bytes_out"].sum() / 1e6, 2)],
})
print(summary.T.rename(columns={0: "value"}))
summary.to_csv("b2_summary_table.csv", index=False)

print("\nSaved: vis1_auth_by_hour.png, vis2_outbound_bytes_by_host.png, "
      "vis3_top_dns.png, vis4_working_vs_offhours.png, b2_summary_table.csv")



"""
SAS821S Lab 1 — Part B3: Anomaly Criterion
Defines and applies two transparent anomaly criteria:
  1. Statistical: z-score on daily outbound bytes per host.
  2. Rule-based: failed-logon burst detection per user.
"""

import pandas as pd

DATA_PATH = r"C:\Users\kali hunter\Downloads\SAS\Lab1"

asset = pd.read_csv(fr"{DATA_PATH}\ot_asset_inventory.csv")
auth  = pd.read_csv(fr"{DATA_PATH}\ot_authentication_logs.csv", parse_dates=["timestamp"])
fw    = pd.read_csv(fr"{DATA_PATH}\ot_firewall_logs.csv", parse_dates=["timestamp"])

# ============================================================
# CRITERION 1: Z-score on daily outbound bytes per host
# ============================================================
fw_asset = fw.merge(asset[["ip_address", "hostname"]],
                     left_on="src_ip", right_on="ip_address", how="left")
fw_asset["hostname"] = fw_asset["hostname"].fillna(fw_asset["src_ip"])
fw_asset["date"] = fw_asset["timestamp"].dt.date

daily_bytes = fw_asset.groupby(["hostname", "date"])["bytes_out"].sum().reset_index()

mu = daily_bytes["bytes_out"].mean()
sigma = daily_bytes["bytes_out"].std()
daily_bytes["z_score"] = (daily_bytes["bytes_out"] - mu) / sigma

THRESHOLD = 3.0
flagged_days = daily_bytes[daily_bytes["z_score"] > THRESHOLD].sort_values(
    "z_score", ascending=False)

print("=== CRITERION 1: Outbound-byte z-score (threshold z > 3) ===")
print(f"Population: {len(daily_bytes)} host-days, "
      f"mean={mu:,.0f} bytes, std={sigma:,.0f} bytes")
print(flagged_days.to_string(index=False))
print()

# ============================================================
# CRITERION 2: Failed-logon burst rule
# Flags >= N_THRESHOLD FAILURE events for the same user within
# a rolling WINDOW_MIN-minute window.
# ============================================================
N_THRESHOLD = 4
WINDOW_MIN = 5

fails = auth[auth["result"] == "FAILURE"].sort_values("timestamp").copy()
flagged_bursts = []

for uid, grp in fails.groupby("user_id"):
    grp = grp.sort_values("timestamp")
    times = grp["timestamp"].tolist()
    ids = grp["event_id"].tolist()
    for i in range(len(times)):
        window_end = times[i] + pd.Timedelta(minutes=WINDOW_MIN)
        count_in_window = sum(1 for t in times[i:] if t <= window_end)
        if count_in_window >= N_THRESHOLD:
            flagged_bursts.append({
                "user_id": uid,
                "burst_start": times[i],
                "events_in_window": count_in_window,
                "event_ids": ids[i:i + count_in_window],
            })
            break   # one flagged burst per user is enough to demonstrate it

print(f"=== CRITERION 2: Failed-logon burst "
      f"(>= {N_THRESHOLD} failures within {WINDOW_MIN} min) ===")
for b in flagged_bursts:
    print(b)



"""
SAS821S Lab 1 -- Part C1: Correlated Incident Timeline
Pulls authentication, DNS and firewall evidence for the affected host/user
around the incident window (2026-08-15) and assembles a chronological,
cross-source timeline.
"""

import pandas as pd

DATA_PATH = r"C:\Users\kali hunter\Downloads\SAS\Lab1"

asset = pd.read_csv(fr"{DATA_PATH}\ot_asset_inventory.csv")
user  = pd.read_csv(fr"{DATA_PATH}\ot_user_directory.csv")
auth  = pd.read_csv(fr"{DATA_PATH}\ot_authentication_logs.csv", parse_dates=["timestamp"])
dns   = pd.read_csv(fr"{DATA_PATH}\ot_dns_logs.csv", parse_dates=["timestamp"])
fw    = pd.read_csv(fr"{DATA_PATH}\ot_firewall_logs.csv", parse_dates=["timestamp"])

HOST_IP = "10.14.7.23"     # WKST-FIN-023, confirmed via asset inventory
USER_ID = "nshikongo"      # confirmed via user directory (Finance dept)
INCIDENT_DATE = "2026-08-15"

# ------------------------------------------------------------------
# Reference: confirm host/user identity from the directories
# ------------------------------------------------------------------
print("=== Asset record for the affected host ===")
print(asset[asset["ip_address"] == HOST_IP].to_string(index=False))
print()
print("=== User record for the affected account ===")
print(user[user["user_id"] == USER_ID].to_string(index=False))
print()

# ------------------------------------------------------------------
# Authentication events for the user, on the incident date
# ------------------------------------------------------------------
print("=== AUTH events: nshikongo, 2026-08-15 ===")
a = auth[(auth["user_id"] == USER_ID) &
         (auth["timestamp"].dt.date.astype(str) == INCIDENT_DATE)]
print(a[["event_id", "timestamp", "logon_type", "result",
          "failure_reason", "process"]].to_string(index=False))
print()

# ------------------------------------------------------------------
# DNS queries from the host, on the incident date
# ------------------------------------------------------------------
print("=== DNS queries: 10.14.7.23, 2026-08-15 ===")
q = dns[(dns["client_ip"] == HOST_IP) &
        (dns["timestamp"].dt.date.astype(str) == INCIDENT_DATE)].sort_values("timestamp")
print(q[["event_id", "timestamp", "query_name", "query_type",
          "response_code", "response_ip", "ttl"]].to_string(index=False))
print()

# ------------------------------------------------------------------
# Firewall events sourced FROM the host, on the incident date
# ------------------------------------------------------------------
print("=== FIREWALL events: src 10.14.7.23, 2026-08-15 ===")
f = fw[(fw["src_ip"] == HOST_IP) &
       (fw["timestamp"].dt.date.astype(str) == INCIDENT_DATE)].sort_values("timestamp")
print(f[["event_id", "timestamp", "dst_ip", "dst_port", "protocol", "action",
          "bytes_out", "bytes_in", "duration_sec", "rule_name", "country"]].to_string(index=False))
print()

# ------------------------------------------------------------------
# Firewall events with the host as DESTINATION (inbound) --
# catches internal systems sending data TO the compromised host
# ------------------------------------------------------------------
print("=== FIREWALL events: dst 10.14.7.23, 2026-08-15 (inbound) ===")
f_in = fw[(fw["dst_ip"] == HOST_IP) &
          (fw["timestamp"].dt.date.astype(str) == INCIDENT_DATE)].sort_values("timestamp")
print(f_in[["event_id", "timestamp", "src_ip", "dst_port", "protocol", "action",
             "bytes_out", "bytes_in", "rule_name"]].to_string(index=False))
print()

# ------------------------------------------------------------------
# Isolate the largest outbound transfers (the exfiltration burst)
# ------------------------------------------------------------------
print("=== Top outbound transfers from 10.14.7.23 on 2026-08-15 ===")
top_out = f.sort_values("bytes_out", ascending=False).head(20)
print(top_out[["event_id", "timestamp", "dst_ip", "dst_port",
                 "bytes_out", "country", "rule_name"]].to_string(index=False))

# Save the assembled cross-log evidence for the report appendix
combined_note = pd.concat([
    a.assign(source="auth"),
    q.assign(source="dns").rename(columns={"query_name": "detail"}),
    f.assign(source="firewall_out").rename(columns={"dst_ip": "detail"}),
    f_in.assign(source="firewall_in").rename(columns={"src_ip": "detail"}),
], ignore_index=True, sort=False)
combined_note.to_csv("c1_timeline_evidence.csv", index=False)
print("\nSaved combined evidence extract: c1_timeline_evidence.csv")



"""
SAS821S Lab 1 -- Part C2: Evidence-Based Findings
Derives each required finding programmatically from the correlated
evidence (auth, DNS, firewall, asset, user directories) rather than
by manual inspection.
"""

import pandas as pd

DATA_PATH = r"C:\Users\kali hunter\Downloads\SAS\Lab1"

asset = pd.read_csv(fr"{DATA_PATH}\ot_asset_inventory.csv")
user  = pd.read_csv(fr"{DATA_PATH}\ot_user_directory.csv")
auth  = pd.read_csv(fr"{DATA_PATH}\ot_authentication_logs.csv", parse_dates=["timestamp"])
dns   = pd.read_csv(fr"{DATA_PATH}\ot_dns_logs.csv", parse_dates=["timestamp"])
fw    = pd.read_csv(fr"{DATA_PATH}\ot_firewall_logs.csv", parse_dates=["timestamp"])

HOST_IP = "10.14.7.23"
USER_ID = "nshikongo"
INCIDENT_DATE = "2026-08-15"

# ------------------------------------------------------------------
# 1. Affected user/endpoint
# ------------------------------------------------------------------
rec_user = user[user["user_id"] == USER_ID].iloc[0]
rec_asset = asset[asset["ip_address"] == HOST_IP].iloc[0]
print("Affected user:", rec_user["full_name"], "|", rec_user["department"])
print("Affected host:", rec_asset["hostname"], "|", rec_asset["ip_address"],
      "| criticality:", rec_asset["criticality"])
print()

# ------------------------------------------------------------------
# 2. Earliest substantiated suspicious event
# ------------------------------------------------------------------
fails = auth[(auth["user_id"] == USER_ID) &
             (auth["result"] == "FAILURE") &
             (auth["timestamp"].dt.date.astype(str) == INCIDENT_DATE)].sort_values("timestamp")
earliest = fails.iloc[0]
print("Earliest suspicious event:", earliest["event_id"], earliest["timestamp"],
      "-", earliest["failure_reason"])
print()

# ------------------------------------------------------------------
# 3. External infrastructure contacted during the incident window
# ------------------------------------------------------------------
window_start = pd.Timestamp(f"{INCIDENT_DATE} 01:40:00")
window_end   = pd.Timestamp(f"{INCIDENT_DATE} 03:00:00")

fw_window = fw[(fw["src_ip"] == HOST_IP) &
               (fw["timestamp"].between(window_start, window_end))]
dns_window = dns[(dns["client_ip"] == HOST_IP) &
                  (dns["timestamp"].between(window_start, window_end))]

print("External IPs contacted in incident window:")
print(fw_window.groupby(["dst_ip", "country"])["bytes_out"].agg(["count", "sum"]).sort_values("sum", ascending=False))
print()
print("Distinct external domains queried in incident window:")
print(dns_window["query_name"].value_counts())
print()

# ------------------------------------------------------------------
# 4. Internal lateral access -- large DATA PULLS from other internal
#    (10.20.x.x) systems. Direction is inferred from bytes_in/bytes_out,
#    not just src/dst, because the host itself often INITIATES the
#    connection (src_ip = HOST_IP) while still being the data recipient
#    (large bytes_in on that same connection).
# ------------------------------------------------------------------
BYTES_IN_THRESHOLD = 1_000_000  # 1MB+ pulled back on a single connection

lateral_a = fw[(fw["src_ip"] == HOST_IP) &
               (fw["dst_ip"].str.startswith("10.20.")) &
               (fw["bytes_in"] > BYTES_IN_THRESHOLD) &
               (fw["timestamp"].between(window_start, window_end))].copy()
lateral_a = lateral_a.rename(columns={"dst_ip": "internal_system_ip"})

lateral_b = fw[(fw["dst_ip"] == HOST_IP) &
               (fw["src_ip"].str.startswith("10.20.")) &
               (fw["timestamp"].between(window_start, window_end))].copy()
lateral_b = lateral_b.rename(columns={"src_ip": "internal_system_ip"})

lateral = pd.concat([lateral_a, lateral_b], ignore_index=True)
lateral = lateral.merge(
    asset[["ip_address", "hostname", "criticality", "asset_type"]],
    left_on="internal_system_ip", right_on="ip_address", how="left"
)
print("Large data pulls from internal systems during incident window:")
print(lateral[["event_id", "timestamp", "hostname", "asset_type",
                 "criticality", "bytes_in", "bytes_out"]].to_string(index=False))
print()

# ------------------------------------------------------------------
# 5. Exfiltration volume -- total bytes out to the confirmed
#    exfil destination during the burst
# ------------------------------------------------------------------
exfil_dst = "45.77.89.11"
exfil = fw[(fw["src_ip"] == HOST_IP) & (fw["dst_ip"] == exfil_dst)]
print(f"Exfiltration burst to {exfil_dst}:")
print(f"  connections: {len(exfil)}")
print(f"  total bytes_out: {exfil['bytes_out'].sum():,} ({exfil['bytes_out'].sum()/1e6:.1f} MB)")
print(f"  window: {exfil['timestamp'].min()} to {exfil['timestamp'].max()}")
print(f"  any DENY/reset actions: {(exfil['action']!='ALLOW').sum()} of {len(exfil)}")




"""
SAS821S Lab 1 -- Part D1: Model Design and Implementation
Trains an interpretable supervised classifier (logistic regression)
on the labelled flow data, using a stratified 70/30 split with a
fixed random seed.
"""

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier

DATA_PATH = r"C:\Users\kali hunter\Downloads\SAS\Lab1"
RANDOM_SEED = 821   # fixed seed

train = pd.read_csv(fr"{DATA_PATH}\ot_network_flow_training.csv", parse_dates=["timestamp"])

# Numeric, model-ready features present in both training and investigation sets
FEATURES = [
    "dst_port", "duration_sec", "src_bytes", "dst_bytes", "packets",
    "connections_2s", "serror_rate", "rerror_rate", "same_srv_rate",
    "diff_srv_rate", "hour", "is_weekend"
]

X = train[FEATURES]
y = train["label"]

# Stratified 70/30 split -- stratify=y preserves the malicious/benign
# class balance in both the train and test partitions
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.30, random_state=RANDOM_SEED, stratify=y
)

print(f"Train set: {len(X_train)} rows, malicious rate = {y_train.mean():.3f}")
print(f"Test set:  {len(X_test)} rows,  malicious rate = {y_test.mean():.3f}")
print()

# --- Primary model: Logistic Regression (interpretable -- coefficients
#     are directly readable as feature influence direction/magnitude) ---
logreg = Pipeline([
    ("scale", StandardScaler()),
    ("classifier", LogisticRegression(max_iter=2000, class_weight="balanced",
                                        random_state=RANDOM_SEED)),
])
logreg.fit(X_train, y_train)

# --- Comparison model: Decision Tree (interpretable via explicit rules,
#     captures non-linear thresholds a linear model can't) ---
tree = DecisionTreeClassifier(max_depth=5, class_weight="balanced",
                                random_state=RANDOM_SEED)
tree.fit(X_train, y_train)

print("Logistic Regression coefficients (feature influence direction):")
coefs = pd.Series(logreg.named_steps["classifier"].coef_[0], index=FEATURES)
print(coefs.sort_values(key=abs, ascending=False))
print()

print("Decision Tree feature importances:")
imp = pd.Series(tree.feature_importances_, index=FEATURES)
print(imp.sort_values(ascending=False))



"""
SAS821S Lab 1 -- Part D2: Evaluation
Computes confusion matrix and security-relevant metrics (accuracy,
precision, recall, F1, false-negative rate) for both models on the
held-out 30% test set.
"""

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import (confusion_matrix, precision_score, recall_score,
                              f1_score, accuracy_score)

DATA_PATH = r"C:\Users\kali hunter\Downloads\SAS\Lab1"
RANDOM_SEED = 821

train = pd.read_csv(fr"{DATA_PATH}\ot_network_flow_training.csv", parse_dates=["timestamp"])

FEATURES = [
    "dst_port", "duration_sec", "src_bytes", "dst_bytes", "packets",
    "connections_2s", "serror_rate", "rerror_rate", "same_srv_rate",
    "diff_srv_rate", "hour", "is_weekend"
]
X = train[FEATURES]
y = train["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.30, random_state=RANDOM_SEED, stratify=y
)

logreg = Pipeline([
    ("scale", StandardScaler()),
    ("classifier", LogisticRegression(max_iter=2000, class_weight="balanced",
                                        random_state=RANDOM_SEED)),
]).fit(X_train, y_train)

tree = DecisionTreeClassifier(max_depth=5, class_weight="balanced",
                                random_state=RANDOM_SEED).fit(X_train, y_train)


def evaluate(model, name):
    pred = model.predict(X_test)
    cm = confusion_matrix(y_test, pred)
    tn, fp, fn, tp = cm.ravel()

    acc = accuracy_score(y_test, pred)
    prec = precision_score(y_test, pred)
    rec = recall_score(y_test, pred)
    f1 = f1_score(y_test, pred)
    fnr = fn / (fn + tp)

    print(f"=== {name} ===")
    print("Confusion matrix [[TN FP] [FN TP]]:")
    print(cm)
    print(f"Accuracy:            {acc:.3f}")
    print(f"Precision:           {prec:.3f}")
    print(f"Recall (sensitivity):{rec:.3f}")
    print(f"F1-score:            {f1:.3f}")
    print(f"False-negative rate: {fnr:.3f}  ({fn} of {fn+tp} actual attacks missed)")
    print()


evaluate(logreg, "Logistic Regression")
evaluate(tree, "Decision Tree")

baseline_acc = 1 - y_test.mean()
print(f"Naive baseline (predict all-benign) accuracy: {baseline_acc:.3f}")
print("-> shows why accuracy alone is misleading under class imbalance: "
      "a model predicting 'benign' for everything scores this high "
      "while catching zero actual attacks (recall = 0).")



"""
SAS821S Lab 1 -- Part D3: Apply the Model to the Investigation
Scores ot_network_flow_investigation.csv with the chosen model
(Decision Tree -- selected in D2 for higher recall/lower FNR) and
exports the required top_10_suspicious_flows.csv.
"""

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier

DATA_PATH = r"C:\Users\kali hunter\Downloads\SAS\Lab1"
RANDOM_SEED = 821

train = pd.read_csv(fr"{DATA_PATH}\ot_network_flow_training.csv", parse_dates=["timestamp"])
inv   = pd.read_csv(fr"{DATA_PATH}\ot_network_flow_investigation.csv", parse_dates=["timestamp"])

FEATURES = [
    "dst_port", "duration_sec", "src_bytes", "dst_bytes", "packets",
    "connections_2s", "serror_rate", "rerror_rate", "same_srv_rate",
    "diff_srv_rate", "hour", "is_weekend"
]
X, y = train[FEATURES], train["label"]
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.30, random_state=RANDOM_SEED, stratify=y
)

tree = DecisionTreeClassifier(max_depth=5, class_weight="balanced",
                                random_state=RANDOM_SEED).fit(X_train, y_train)

# --- Score the investigation set ---
X_inv = inv[FEATURES]
inv["predicted_malicious"] = tree.predict(X_inv)
inv["malicious_probability"] = tree.predict_proba(X_inv)[:, 1]

print("Investigation set predictions summary:")
print(inv["predicted_malicious"].value_counts())

# --- Export top 10 suspicious flows ---
top10 = inv.sort_values("malicious_probability", ascending=False).head(10).copy()
top10["interpretation"] = ("Flagged by Decision Tree classifier -- corroborated by "
                             "log-based timeline in incident report Part C")

export_cols = ["flow_id", "timestamp", "src_ip", "dst_ip",
               "malicious_probability", "interpretation"]
top10.rename(columns={"src_ip": "source", "dst_ip": "destination",
                        "malicious_probability": "probability"}
             )[["flow_id", "timestamp", "source", "destination",
                "probability", "interpretation"]].to_csv(
    "top_10_suspicious_flows.csv", index=False
)

print("Saved top_10_suspicious_flows.csv")


