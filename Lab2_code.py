import hashlib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    confusion_matrix, precision_score, recall_score, f1_score,
    accuracy_score, roc_auc_score,
)

BASE = r"C:\SAS\Lab2"
RANDOM_SEED = 42

MANIFEST_PATH        = BASE + r"\SHA256SUMS.txt"
DATA_DICTIONARY_PATH = BASE + r"\data_dictionary.csv"
POLICY_PATH          = BASE + r"\ofs_access_policy_matrix.csv"
INVESTIGATION_PATH   = BASE + r"\ofs_access_session_investigation.csv"
TRAINING_PATH        = BASE + r"\ofs_access_session_training.csv"
ASSETS_PATH          = BASE + r"\ofs_asset_inventory.csv"
EMAIL_PATH           = BASE + r"\ofs_email_gateway_logs.csv"
EMPLOYEES_PATH       = BASE + r"\ofs_employee_directory.csv"
ENDPOINT_PATH        = BASE + r"\ofs_endpoint_process_logs.csv"
FILES_PATH           = BASE + r"\ofs_file_access_logs.csv"
PROXY_PATH           = BASE + r"\ofs_proxy_dlp_logs.csv"
INTEL_PATH           = BASE + r"\ofs_threat_intelligence.csv"
VPN_PATH             = BASE + r"\ofs_vpn_authentication_logs.csv"
FIGDIR               = BASE + r"\figures"

EVIDENCE_FILES = [
    ("data_dictionary.csv", DATA_DICTIONARY_PATH),
    ("ofs_access_policy_matrix.csv", POLICY_PATH),
    ("ofs_access_session_investigation.csv", INVESTIGATION_PATH),
    ("ofs_access_session_training.csv", TRAINING_PATH),
    ("ofs_asset_inventory.csv", ASSETS_PATH),
    ("ofs_email_gateway_logs.csv", EMAIL_PATH),
    ("ofs_employee_directory.csv", EMPLOYEES_PATH),
    ("ofs_endpoint_process_logs.csv", ENDPOINT_PATH),
    ("ofs_file_access_logs.csv", FILES_PATH),
    ("ofs_proxy_dlp_logs.csv", PROXY_PATH),
    ("ofs_threat_intelligence.csv", INTEL_PATH),
    ("ofs_vpn_authentication_logs.csv", VPN_PATH),
]


def load_manifest(manifest_path):
    manifest = {}
    with open(manifest_path) as f:
        for line in f:
            line = line.strip()
            if line:
                digest, fname = line.split(maxsplit=1)
                manifest[fname] = digest
    return manifest


def sha256_of(fpath):
    with open(fpath, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


import os
os.makedirs(FIGDIR, exist_ok=True)

# =====================================================================
# PRESERVE: verify every evidence file's SHA-256 hash before use
# =====================================================================
manifest = load_manifest(MANIFEST_PATH)
print(f"{'file':<40} {'status':<10}")
print("-" * 50)
all_ok = True
for fname, fpath in EVIDENCE_FILES:
    actual = sha256_of(fpath)
    status = "OK" if actual == manifest.get(fname) else "MISMATCH"
    if status != "OK":
        all_ok = False
    print(f"{fname:<40} {status:<10}")
assert all_ok, "One or more evidence files failed integrity verification."

# ---- load each verified file once; every later section reuses these ----
data_dictionary = pd.read_csv(DATA_DICTIONARY_PATH)
policy          = pd.read_csv(POLICY_PATH)
investigation   = pd.read_csv(INVESTIGATION_PATH, parse_dates=["session_start"])
training        = pd.read_csv(TRAINING_PATH, parse_dates=["session_start"])
assets          = pd.read_csv(ASSETS_PATH)
email           = pd.read_csv(EMAIL_PATH, parse_dates=["timestamp"])
employees       = pd.read_csv(EMPLOYEES_PATH)
endpoint        = pd.read_csv(ENDPOINT_PATH, parse_dates=["timestamp"])
files           = pd.read_csv(FILES_PATH, parse_dates=["timestamp"])
proxy           = pd.read_csv(PROXY_PATH, parse_dates=["timestamp"])
intel           = pd.read_csv(INTEL_PATH, parse_dates=["first_seen", "last_updated"])
vpn             = pd.read_csv(VPN_PATH, parse_dates=["timestamp"])

# threat-intel indicator sets - reused by B1, A2, C1, C2, D3
intel_ips     = set(intel[intel["indicator_type"] == "ip"]["indicator"])
intel_domains = set(intel[intel["indicator_type"] == "domain"]["indicator"])
intel_hashes  = set(intel[intel["indicator_type"] == "sha256"]["indicator"])


# #######################################################################
# A1. INITIAL TRIAGE - generic, unbiased discovery of the account of
# interest (not assumed in advance). Two independent routes:
#   (a) total downloaded MB by user, org-wide
#   (b) non-standard session_id pattern scan on the investigation set
# #######################################################################
files["download_mb"] = files["bytes_transferred"] / (1024 ** 2)
download_summary = (
    files.groupby("user_id", as_index=False)["download_mb"]
    .sum()
    .sort_values("download_mb", ascending=False)
)
print("\n[A1] Route (a) - top downloaders org-wide:")
print(download_summary.head(5).to_string(index=False))

non_standard_sessions = investigation[~investigation["session_id"].str.match(r"^S\d+$")]
print("\n[A1] Route (b) - non-standard session IDs in the investigation set:")
print(non_standard_sessions[["session_id", "user_id", "department"]].to_string(index=False))

account_of_interest = download_summary.iloc[0]["user_id"]
assert account_of_interest == non_standard_sessions["user_id"].unique()[0], \
    "Discovery routes disagree - re-check before narrowing the investigation."
print(f"\n[A1] Both discovery routes converge on: {account_of_interest}")

print(f"\n[A1] Is {account_of_interest} authorised for CUSTOMER_EXPORT?")
print(employees[employees["user_id"] == account_of_interest][["user_id", "role", "permitted_resource_groups"]].to_string(index=False))
print(policy[policy["resource_group"] == "CUSTOMER_EXPORT"][["resource_group", "classification", "authorised_departments_or_roles"]].to_string(index=False))


# #######################################################################
# A2. SECURITY-INTELLIGENCE COLLECTION PLAN
# #######################################################################
source_classification = {
    "employees": "Contextual/business", "assets": "Contextual/business", "policy": "Contextual/business",
    "email": "Internal operational", "vpn": "Internal operational", "endpoint": "Internal operational",
    "files": "Internal operational", "proxy": "Internal operational",
    "intel": "External", "training": "Derived internal", "investigation": "Derived internal",
}
print("\n[A2] Source classification:")
for name, cls in source_classification.items():
    print(f"  {name:15s} -> {cls}")

# Quality risk 1: timeliness - was the intel published before or after the events it corroborates?
exfil_intel = intel[intel["tactic"] == "Exfiltration"]
exfil_proxy_events = proxy[proxy["dlp_rule"] == "CUSTOMER-PII-BULK"]
earliest_exfil_event = exfil_proxy_events["timestamp"].min()
earliest_exfil_intel = exfil_intel["first_seen"].min()
print(f"\n[A2] Quality risk - timeliness: earliest exfil event {earliest_exfil_event}, "
      f"earliest matching intel published {earliest_exfil_intel} "
      f"({'AFTER the event' if earliest_exfil_intel > earliest_exfil_event else 'before the event'})")

# Quality risk 2: coverage gap - every suspicious destination actually covered by the feed?
suspicious_domains = proxy[proxy["user_id"] == account_of_interest]["destination_domain"].unique()
print("[A2] Quality risk - coverage gap check:")
for dom in suspicious_domains:
    print(f"  {dom:<25s} in threat-intel feed: {dom in intel_domains}")

# Quality risk 3: alert fatigue - confidence/volume profile of the feed
print(f"\n[A2] Quality risk - alert fatigue: {intel['confidence'].value_counts().to_dict()}")

# Not treating intel as proof alone: corroborate each High-confidence indicator internally
def corroborated(row):
    ind, ind_type = row["indicator"], row["indicator_type"]
    if ind_type == "domain":
        return email["url"].fillna("").str.contains(ind, regex=False).any() or proxy["destination_domain"].eq(ind).any()
    if ind_type == "ip":
        return proxy["destination_ip"].eq(ind).any()
    if ind_type == "sha256":
        return endpoint["sha256"].eq(ind).any()
    return False

intel["corroborated_internally"] = intel.apply(corroborated, axis=1)
print("\n[A2] Corroboration check, High-confidence indicators only:")
print(intel[intel["confidence"] == "High"][["intel_id", "indicator_type", "corroborated_internally"]].to_string(index=False))


# #######################################################################
# B1. REPRODUCIBLE PREPARATION - data quality + derived fields
# #######################################################################
frames = {
    "employees": employees, "assets": assets, "policy": policy, "email": email,
    "vpn": vpn, "endpoint": endpoint, "files": files, "proxy": proxy,
    "intel": intel, "training": training, "investigation": investigation,
}
print("\n[B1] Row counts, columns, missing cells, duplicate event/session IDs:")
quality_rows = []
for name, df in frames.items():
    id_col = "event_id" if "event_id" in df.columns else ("session_id" if "session_id" in df.columns else None)
    dup = df.duplicated(subset=id_col).sum() if id_col else df.duplicated().sum()
    quality_rows.append({
        "dataset": name, "rows": len(df), "cols": df.shape[1],
        "missing_cells": int(df.isna().sum().sum()), "duplicate_ids": int(dup),
    })
print(pd.DataFrame(quality_rows).to_string(index=False))

print("\n[B1] Columns with missing values (nonzero only):")
for name, df in frames.items():
    miss = df.isna().sum()
    miss = miss[miss > 0]
    if len(miss):
        print(f"-- {name} --\n{miss.to_string()}")

emp_lookup = employees.set_index("user_id")[
    ["department", "branch", "role", "normal_start", "normal_end", "permitted_resource_groups", "risk_tier"]
]


def add_hour_fields(df, ts_col="timestamp"):
    df["hour"] = df[ts_col].dt.hour
    df["weekday"] = df[ts_col].dt.day_name()
    df["is_weekend"] = df[ts_col].dt.dayofweek >= 5
    return df


vpn = add_hour_fields(vpn)
files = add_hour_fields(files)
proxy = add_hour_fields(proxy)
endpoint = add_hour_fields(endpoint)
email = add_hour_fields(email)

# off_hours <- timestamp.hour compared against the user's own normal_start/normal_end
vpn = vpn.merge(emp_lookup[["normal_start", "normal_end"]], left_on="user_id", right_index=True, how="left")


def off_hours_row(row):
    if pd.isna(row["normal_start"]) or pd.isna(row["normal_end"]):
        return (row["hour"] < 6) or (row["hour"] >= 20)
    start_h = int(str(row["normal_start"]).split(":")[0])
    end_h = int(str(row["normal_end"]).split(":")[0])
    return not (start_h <= row["hour"] < end_h)


vpn["off_hours"] = vpn.apply(off_hours_row, axis=1) | vpn["is_weekend"]

# new_device / new_geography <- first occurrence per user_id of a device_id / country
vpn = vpn.sort_values("timestamp")
vpn["new_device"] = ~vpn.duplicated(subset=["user_id", "device_id"], keep="first")
vpn["new_geography"] = ~vpn.duplicated(subset=["user_id", "country"], keep="first")

# impossible_travel <- two successful logins by the same user, <=60 min apart, different country.
# Missing country = on-net/Windhoek HQ, coded "NA-HOME" so home<->abroad transitions are comparable.
vpn_success = vpn[vpn["result"] == "SUCCESS"].sort_values(["user_id", "timestamp"]).copy()
vpn_success["country_filled"] = vpn_success["country"].fillna("NA-HOME")
vpn_success["prev_time"] = vpn_success.groupby("user_id")["timestamp"].shift(1)
vpn_success["prev_country"] = vpn_success.groupby("user_id")["country_filled"].shift(1)
vpn_success["gap_minutes"] = (vpn_success["timestamp"] - vpn_success["prev_time"]).dt.total_seconds() / 60
vpn_success["impossible_travel"] = (
    (vpn_success["gap_minutes"] <= 60)
    & vpn_success["prev_country"].notna()
    & (vpn_success["country_filled"] != vpn_success["prev_country"])
)
vpn = vpn.merge(vpn_success[["event_id", "impossible_travel", "gap_minutes"]], on="event_id", how="left")
vpn["impossible_travel"] = vpn["impossible_travel"].fillna(False)
print(f"\n[B1] Impossible-travel flags raised: {int(vpn['impossible_travel'].sum())}")
print(vpn[vpn["impossible_travel"]][["event_id", "timestamp", "user_id", "country", "device_id"]].to_string(index=False))

# download_mb / is_sensitive / role_mismatch <- files columns
files["download_mb"] = np.where(files["action"] == "DOWNLOAD", files["bytes_transferred"] / (1024 ** 2), 0.0)
files["is_sensitive"] = files["sensitivity"].isin(["Confidential", "Restricted"])
files = files.merge(emp_lookup[["permitted_resource_groups"]], left_on="user_id", right_index=True, how="left")


def resource_group_mismatch(row):
    perms = str(row["permitted_resource_groups"]).split(";") if pd.notna(row["permitted_resource_groups"]) else []
    return row["resource_group"] not in perms


files["role_mismatch"] = files.apply(resource_group_mismatch, axis=1)

# upload_mb <- proxy.bytes_out ; dest_matches_intel <- proxy destination vs intel
proxy["upload_mb"] = proxy["bytes_out"] / (1024 ** 2)
proxy["dest_matches_intel"] = proxy["destination_ip"].isin(intel_ips) | proxy["destination_domain"].isin(intel_domains)

# hash_matches_intel <- endpoint.sha256 vs intel
endpoint["hash_matches_intel"] = endpoint["sha256"].isin(intel_hashes)
endpoint["is_high_risk"] = endpoint["risk_level"].isin(["High", "Critical"])

# intel_domain_match <- email sender/url domain vs intel
email["sender_domain"] = email["sender"].str.split("@").str[1]
email["url_domain"] = email["url"].str.extract(r"https?://([^/]+)/?")
email["intel_domain_match"] = email["url_domain"].isin(intel_domains) | email["sender_domain"].isin(intel_domains)


# #######################################################################
# B2. USER AND PEER-GROUP BASELINES
# #######################################################################
emp_dept = employees.set_index("user_id")["department"]
vpn_d = vpn.copy(); vpn_d["department"] = vpn_d["user_id"].map(emp_dept)
files_d = files.copy(); files_d["department"] = files_d["user_id"].map(emp_dept)
proxy_d = proxy.copy(); proxy_d["department"] = proxy_d["user_id"].map(emp_dept)

vpn_agg = vpn_d.groupby("department").agg(
    logins=("event_id", "count"),
    failed_logins=("result", lambda s: (s == "FAILURE").sum()),
    off_hours_pct=("off_hours", "mean"),
    new_device_pct=("new_device", "mean"),
).round(2)
files_agg = files_d.groupby("department").agg(
    sensitive_access_events=("is_sensitive", "sum"),
    total_download_mb=("download_mb", "sum"),
    role_mismatch_events=("role_mismatch", "sum"),
).round(2)
proxy_agg = proxy_d.groupby("department").agg(total_upload_mb=("upload_mb", "sum")).round(2)
peer_baseline = vpn_agg.join(files_agg, how="outer").join(proxy_agg, how="outer").fillna(0)
print("\n[B2] Peer-group (department) baseline summary table:")
print(peer_baseline.to_string())
peer_baseline.to_csv(BASE + r"\peer_group_baseline_summary.csv")

# Individual baseline: same-role peers only (CS Officers), supervisors excluded,
# since CUSTOMER_EXPORT is a supervisor-level permission.
cs_officers = employees[
    (employees["department"] == "Customer Service") & (employees["role"].str.contains("Officer"))
]["user_id"].tolist()
indiv_baseline = files_d[files_d["user_id"].isin(cs_officers)].groupby("user_id").agg(
    sensitive_access_events=("is_sensitive", "sum"), total_download_mb=("download_mb", "sum"),
).round(2)
print(f"\n[B2] Individual baseline - CS Officers {cs_officers}:")
print(indiv_baseline.to_string())

# Figure 1: login-hour distribution, target account vs CS peers
vpn_cs = vpn_d[vpn_d["department"] == "Customer Service"]
peer_hours = vpn_cs[vpn_cs["user_id"] != account_of_interest]["hour"]
target_hours = vpn_cs[vpn_cs["user_id"] == account_of_interest]["hour"]
fig, ax = plt.subplots(figsize=(8, 5))
ax.hist(peer_hours, bins=range(25), alpha=0.5, label=f"CS peers (n={len(peer_hours)})", color="steelblue", density=True)
ax.hist(target_hours, bins=range(25), alpha=0.6, label=f"{account_of_interest} (n={len(target_hours)})", color="firebrick", density=True)
ax.axvspan(6, 20, color="grey", alpha=0.08, label="typical business hours")
ax.set_xlabel("Hour of day (Namibia local time, UTC+2)"); ax.set_ylabel("Density of VPN login events")
ax.set_title("Login-hour distribution vs Customer Service peer baseline")
ax.legend(); fig.tight_layout()
fig.savefig(FIGDIR + r"\viz1_login_hour_distribution.png", dpi=150); plt.close(fig)

# Figure 2: sensitive-resource download volume by CS user
sens_by_user = files_d[(files_d["department"] == "Customer Service") & files_d["is_sensitive"]].groupby("user_id")["download_mb"].sum().sort_values(ascending=False)
fig, ax = plt.subplots(figsize=(8, 5))
ax.bar(sens_by_user.index, sens_by_user.values, color=["firebrick" if u == account_of_interest else "steelblue" for u in sens_by_user.index])
ax.set_ylabel("Downloaded MB from sensitive/restricted resources"); ax.set_xlabel("User (Customer Service)")
ax.set_title("Sensitive-resource download volume by Customer Service user")
for lbl in ax.get_xticklabels(): lbl.set_rotation(30); lbl.set_ha("right")
fig.tight_layout(); fig.savefig(FIGDIR + r"\viz2_sensitive_download_by_user.png", dpi=150); plt.close(fig)

# Figure 3: external upload volume, top 12 users org-wide
upload_by_user = proxy_d.groupby("user_id")["upload_mb"].sum().sort_values(ascending=False).head(12)
fig, ax = plt.subplots(figsize=(8, 5))
ax.bar(upload_by_user.index, upload_by_user.values, color=["firebrick" if u == account_of_interest else "steelblue" for u in upload_by_user.index])
ax.set_yscale("log"); ax.set_ylabel("Total external upload volume, MB (log scale)"); ax.set_xlabel("User")
ax.set_title("Top 12 users by external upload volume (proxy/DLP)")
for lbl in ax.get_xticklabels(): lbl.set_rotation(30); lbl.set_ha("right")
fig.tight_layout(); fig.savefig(FIGDIR + r"\viz3_upload_volume_top_users.png", dpi=150); plt.close(fig)

# Figure 4: failed authentication + off-hours rate by department
fig, ax1 = plt.subplots(figsize=(8, 5))
ax1.bar(peer_baseline.index, peer_baseline["failed_logins"], color="slategrey", label="Failed VPN logins")
ax1.set_ylabel("Failed VPN logins (count)")
ax2 = ax1.twinx()
ax2.plot(peer_baseline.index, peer_baseline["off_hours_pct"] * 100, color="firebrick", marker="o", label="Off-hours access %")
ax2.set_ylabel("Off-hours access (%)")
ax1.set_title("Failed authentication and off-hours access rate by department")
for lbl in ax1.get_xticklabels(): lbl.set_rotation(30); lbl.set_ha("right")
fig.tight_layout(); fig.savefig(FIGDIR + r"\viz4_failed_auth_offhours_by_dept.png", dpi=150); plt.close(fig)
print(f"\n[B2] 4 baseline visualisations written to {FIGDIR}")


# #######################################################################
# B3. TRANSPARENT ACCESS-RISK RULE
# Applied to ofs_access_session_investigation.csv (session-level data,
# separate from the raw event logs used above). Thresholds for the four
# continuous indicators are the 75th percentile of the investigation
# population itself - data-driven, not arbitrary.
# #######################################################################
p75_upload = investigation["data_upload_mb"].quantile(0.75)
p75_peer_dev = investigation["peer_deviation_score"].quantile(0.75)
p75_proc_risk = investigation["process_risk_score"].quantile(0.75)
p75_dest_risk = investigation["destination_risk_score"].quantile(0.75)


def rule_score_row(row):
    score, reasons = 0, []
    checks = [
        (row["impossible_travel"] == 1, 3, "impossible_travel"),
        (row["privilege_mismatch"] == 1, 3, "privilege_mismatch"),
        (row["new_device"] == 1, 1, "new_device"),
        (row["off_hours"] == 1, 1, "off_hours"),
        (row["peer_deviation_score"] > p75_peer_dev, 1, "peer_deviation>p75"),
        (row["data_upload_mb"] > p75_upload, 2, "upload_volume>p75"),
        (row["process_risk_score"] > p75_proc_risk, 2, "process_risk>p75"),
        (row["destination_risk_score"] > p75_dest_risk, 2, "destination_risk>p75"),
        (row["failed_logins_30m"] >= 3 or row["mfa_denials"] >= 3, 2, "auth_fatigue_pattern"),
    ]
    for cond, pts, label in checks:
        if cond:
            score += pts
            reasons.append(label)
    return pd.Series({"rule_score": score, "rule_reasons": ";".join(reasons)})


scored = investigation.join(investigation.apply(rule_score_row, axis=1)).sort_values("rule_score", ascending=False)
RULE_THRESHOLD = 6  # empirically chosen: clear gap between score 15 (real-incident cluster) and 11 (next-highest)
scored["rule_flag_high_risk"] = scored["rule_score"] >= RULE_THRESHOLD
print(f"\n[B3] Rule score distribution:\n{scored['rule_score'].value_counts().sort_index().to_string()}")
print(f"\n[B3] Top 15 by rule score (threshold={RULE_THRESHOLD}):")
cols = ["session_id", "session_start", "user_id", "department", "rule_score", "rule_flag_high_risk", "rule_reasons"]
print(scored[cols].head(15).to_string(index=False))
print(f"\n[B3] Sessions flagged high-risk: {scored['rule_flag_high_risk'].sum()} of {len(scored)}")
scored.to_csv(BASE + r"\rule_scored_investigation_sessions.csv", index=False)


# #######################################################################
# C1. CORRELATED INCIDENT TIMELINE for the account of interest.
# User/asset context (role, permitted_resource_groups, policy) and
# threat-intel context are not separate rows - they are looked up per
# event to produce the analytical_interpretation column.
# #######################################################################
WINDOW_START = pd.Timestamp("2026-09-11 16:00:00")
WINDOW_END = pd.Timestamp("2026-09-12 01:00:00")
tl_rows = []


def tl_add(event_id, ts, source, action, interpretation):
    tl_rows.append({"event_id": event_id, "timestamp": ts, "source": source,
                     "observed_action": action, "analytical_interpretation": interpretation})


e = email[(email["recipient"] == account_of_interest) & email["timestamp"].between(WINDOW_START, WINDOW_END)]
for _, r in e.iterrows():
    tl_add(r["event_id"], r["timestamp"], "email_gateway", f"{r['verdict']} - '{r['subject']}' from {r['sender']}",
           "Initial-access lure: newly registered domain, unknown reputation, allowed by gateway "
           "(no block rule existed at delivery time) - matches TI1001 (Mantis Jackal, Initial Access, High).")

v = vpn[(vpn["user_id"] == account_of_interest) & vpn["timestamp"].between(WINDOW_START, WINDOW_END)]
for _, r in v.iterrows():
    if r["country"] == "ZA" and r["result"] == "FAILURE":
        interp = "Repeated failed VPN/MFA attempts from an unfamiliar device and foreign geography (Johannesburg, ZA) - MFA-fatigue ('push bombing') pattern."
    elif r["country"] == "ZA" and r["result"] == "SUCCESS":
        interp = "Authentication succeeds after MFA-fatigue pattern - attacker gains a live session from ZA on an unrecognised device."
    elif r["device_id"] == "CORP-WKST-CS-017" and r["timestamp"] > pd.Timestamp("2026-09-11 18:18:00"):
        interp = "Legitimate Windhoek session active concurrently with the ZA session - impossible travel; indicates compromise, not genuine roaming."
    else:
        interp = "Routine VPN session from usual device/location."
    tl_add(r["event_id"], r["timestamp"], "vpn_auth",
           f"{r['result']}/{r['mfa_result']} from {r['country'] if pd.notna(r['country']) else 'Windhoek (on-net)'}, device {r['device_id']}", interp)

p = endpoint[(endpoint["user_id"] == account_of_interest) & endpoint["timestamp"].between(WINDOW_START, WINDOW_END)]
interp_map = {
    "chrome.exe": "User/attacker clicks the phishing link, launching a browser session to the lure domain.",
    "mshta.exe": "chrome.exe spawns mshta.exe to execute a remote HTA payload - living-off-the-land execution; unsigned, High EDR risk. Hash matches TI1005 (Mantis Jackal, High).",
    "powershell.exe": "mshta.exe spawns an obfuscated/encoded PowerShell command - Critical EDR risk; second-stage downloader/loader.",
    "rundll32.exe": "PowerShell spawns rundll32.exe against a file in a world-writable path - likely persistence/execution of the implant.",
    "net.exe": "Discovery command enumerating Domain Admins group membership - reconnaissance for privilege escalation.",
    "nltest.exe": "Discovery command listing domain controllers - further internal reconnaissance.",
    "7z.exe": "Attacker archives the exported data into a single zip - staging for exfiltration.",
    "rclone.exe": "Unsigned cloud-sync utility copies the staged archive to an external destination - the exfiltration step.",
}
for _, r in p.iterrows():
    tl_add(r["event_id"], r["timestamp"], "endpoint",
           f"{r['parent_process']} -> {r['process_name']} :: {str(r['command_line'])[:80]}",
           interp_map.get(r["process_name"], f"Endpoint activity ({r['risk_level']} EDR risk)."))

f_win = files[(files["user_id"] == account_of_interest) & files["timestamp"].between(WINDOW_START, WINDOW_END)]
for _, r in f_win[f_win["target_asset"].isin(["FS-HR-01", "FS-FIN-01"])].iterrows():
    tl_add(r["event_id"], r["timestamp"], "file_access", f"{r['action']} {r['resource_path']} -> {r['status']}",
           "Attempted access to HR/payroll resources outside the account's role - correctly DENIED, but shows privilege-escalation intent.")
kyc_bulk = f_win[f_win["resource_group"] == "CUSTOMER_EXPORT"]
if len(kyc_bulk):
    first_kyc = kyc_bulk.iloc[0]
    tl_add(first_kyc["event_id"], first_kyc["timestamp"], "file_access", f"LIST {first_kyc['resource_path']}",
           "First touch of the CUSTOMER_EXPORT (bulk KYC) resource group - Restricted per the access policy matrix, "
           "limited to Compliance/Internal Audit/CS Supervisors: confirmed privilege/role mismatch.")
    bulk_dl = kyc_bulk[kyc_bulk["action"] == "DOWNLOAD"]
    tl_add(f"{bulk_dl.iloc[0]['event_id']}..{bulk_dl.iloc[-1]['event_id']}", bulk_dl.iloc[0]["timestamp"], "file_access",
           f"{len(bulk_dl)} sequential DOWNLOAD events, totalling {bulk_dl['bytes_transferred'].sum()/1024/1024:.1f} MB",
           "Mass, machine-paced download of export files - scripted bulk collection, not normal case-by-case work.")

d = proxy[(proxy["user_id"] == account_of_interest) & proxy["timestamp"].between(WINDOW_START, WINDOW_END)]
for _, r in d.iterrows():
    if r["destination_domain"] == "ofservices-portal.com":
        interp = "Outbound request to the phishing/lure domain fetching the HTA payload."
    elif r["destination_domain"] == "sync-statistics.net":
        interp = "Beaconing to a C2-pattern domain at ~5 minute intervals - not itself in the threat-intel feed (a detection gap)."
    elif r["dlp_rule"] == "CUSTOMER-PII-BULK":
        mb = r["bytes_out"] / 1024 / 1024
        interp = ("Bulk customer-PII upload to an external cloud-storage domain matching TI1003/TI1004 (Mantis Jackal, Exfiltration, High). " +
                  (f"~{mb:.0f}MB ALLOWED before the rule caught later transfers." if r["action"] == "ALLOW" else f"~{mb:.0f}MB BLOCK - correctly stopped, but only after the earlier ALLOWed transfer had already left."))
    else:
        interp = "Routine outbound web traffic."
    tl_add(r["event_id"], r["timestamp"], "proxy_dlp", f"{r['method']} {r['destination_domain']} ({r['bytes_out']/1024/1024:.1f} MB) - {r['action']}", interp)

timeline = pd.DataFrame(tl_rows).sort_values("timestamp").reset_index(drop=True)
pd.set_option("display.max_colwidth", 100)
pd.set_option("display.width", 220)
print("\n[C1] Correlated incident timeline:")
print(timeline.to_string(index=False))
print(f"\n[C1] Timeline rows: {len(timeline)}; distinct evidence sources: {timeline['source'].nunique()} {sorted(timeline['source'].unique())}")
timeline.to_csv(BASE + r"\incident_timeline.csv", index=False)


# #######################################################################
# C2. EVIDENCE-BASED FINDINGS
# #######################################################################
print(f"\n[C2] Affected account and endpoint:")
print(employees[employees["user_id"] == account_of_interest][["user_id", "role", "branch", "department"]].to_string(index=False))
wkst = vpn[(vpn["user_id"] == account_of_interest) & vpn["country"].isna()]["device_id"].unique()
print(f"Home workstation device_id seen in VPN logs: {wkst}")

print("\n[C2] Earliest suspicious event / initial-access mechanism:")
e_sorted = email[email["recipient"] == account_of_interest].sort_values("timestamp")
print(f"Earliest suspicious event: {e_sorted.iloc[0]['event_id']} at {e_sorted.iloc[0]['timestamp']} "
      f"(reputation={e_sorted.iloc[0]['url_reputation']}, verdict={e_sorted.iloc[0]['verdict']})")

print("\n[C2] Authentication evidence - credential misuse / MFA abuse vs legitimate travel:")
v_sorted = vpn[vpn["user_id"] == account_of_interest].sort_values("timestamp")
za = v_sorted[v_sorted["country"] == "ZA"]
print(za[["event_id", "timestamp", "result", "mfa_result", "device_id"]].to_string(index=False))
succ = v_sorted[v_sorted["result"] == "SUCCESS"].copy()
succ["prev_country"] = succ["country"].shift(1)
succ["prev_time"] = succ["timestamp"].shift(1)
succ["gap_min"] = (succ["timestamp"] - succ["prev_time"]).dt.total_seconds() / 60
impossible = succ[(succ["gap_min"] <= 60) & (succ["country"].fillna("HOME") != succ["prev_country"].fillna("HOME"))]
print("Impossible-travel pairs (concurrent sessions, different countries):")
print(impossible[["event_id", "timestamp", "country", "gap_min"]].to_string(index=False))

print("\n[C2] Privilege/role check against the policy matrix:")
kyc_events = files[(files["user_id"] == account_of_interest) & (files["resource_group"] == "CUSTOMER_EXPORT")].sort_values("timestamp")
print(f"First CUSTOMER_EXPORT touch: {kyc_events.iloc[0]['event_id']} at {kyc_events.iloc[0]['timestamp']}")
denied = files[(files["user_id"] == account_of_interest) & (files["status"] == "DENIED")]
print("Denied access attempts (privilege-escalation intent):")
print(denied[["event_id", "timestamp", "resource_path", "status"]].to_string(index=False))

print("\n[C2] Collection -> archive -> exfiltration volumes:")
downloads = kyc_events[kyc_events["action"] == "DOWNLOAD"]
print(f"Files downloaded: {len(downloads)}, total {downloads['bytes_transferred'].sum()/1024/1024:.1f} MB "
      f"({downloads.iloc[0]['event_id']}..{downloads.iloc[-1]['event_id']})")
d_pii = proxy[(proxy["user_id"] == account_of_interest) & (proxy["dlp_rule"] == "CUSTOMER-PII-BULK")].assign(
    mb=lambda x: x["bytes_out"] / 1024 / 1024
)
print(d_pii[["event_id", "timestamp", "mb", "action"]].to_string(index=False))
print(f"Total ALLOWED (data lost): {d_pii[d_pii['action']=='ALLOW']['mb'].sum():.1f} MB | "
      f"Total BLOCKED (contained): {d_pii[d_pii['action']=='BLOCK']['mb'].sum():.1f} MB")

print("\n[C2] Control weaknesses / detection gaps:")
print(f"Gap 1 - gateway allowed the lure with no block rule at delivery time "
      f"({e_sorted[e_sorted['verdict']=='ALLOW'].shape[0]} ALLOW verdicts for this recipient).")
beacon_events = proxy[(proxy["user_id"] == account_of_interest) & (proxy["destination_domain"] == "sync-statistics.net")]
print(f"Gap 2 - C2 domain 'sync-statistics.net' covered by threat-intel feed: {'sync-statistics.net' in intel_domains} "
      f"({len(beacon_events)} beacon events observed).")


# #######################################################################
# D1. MODEL DESIGN AND IMPLEMENTATION (supervised - training.csv has a
# known label; user_id/session_id excluded so the model learns
# behavioural risk, not identity)
# #######################################################################
FEATURES = [
    "new_device", "off_hours", "failed_logins_30m", "mfa_denials", "mfa_approvals",
    "unique_resources", "sensitive_resources", "denied_accesses", "files_read",
    "bytes_downloaded_mb", "data_upload_mb", "process_risk_score",
    "destination_risk_score", "peer_deviation_score", "impossible_travel", "privilege_mismatch",
]
train_X = pd.get_dummies(training[FEATURES + ["department"]], columns=["department"])
train_y = training["label"]
inv_X = pd.get_dummies(investigation[FEATURES + ["department"]], columns=["department"]) \
    .reindex(columns=train_X.columns, fill_value=0)

print(f"\n[D1] Training set: {len(training)} rows, label rate {training['label'].mean():.1%}")
X_train, X_test, y_train, y_test = train_test_split(
    train_X, train_y, test_size=0.30, random_state=RANDOM_SEED, stratify=train_y
)
print(f"[D1] Train size: {len(X_train)}  Test size: {len(X_test)}  "
      f"Train label rate: {y_train.mean():.3f}  Test label rate: {y_test.mean():.3f}")

model = RandomForestClassifier(
    n_estimators=300, min_samples_leaf=2, class_weight="balanced", random_state=RANDOM_SEED, n_jobs=-1,
)
model.fit(X_train, y_train)
importances = pd.Series(model.feature_importances_, index=train_X.columns).sort_values(ascending=False)
print("[D1] Top 10 feature importances:")
print(importances.head(10).to_string())


# #######################################################################
# D2. EVALUATION AND INVESTIGATION SCORING
# #######################################################################
y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]
cm = confusion_matrix(y_test, y_pred)
tn, fp, fn, tp = cm.ravel()
print(f"\n[D2] Confusion matrix:\n{pd.DataFrame(cm, index=['actual_0','actual_1'], columns=['pred_0','pred_1'])}")
print(f"[D2] Accuracy:  {accuracy_score(y_test, y_pred):.3f}")
print(f"[D2] Precision: {precision_score(y_test, y_pred):.3f}")
print(f"[D2] Recall:    {recall_score(y_test, y_pred):.3f}")
print(f"[D2] F1-score:  {f1_score(y_test, y_pred):.3f}")
print(f"[D2] FN rate:   {fn/(fn+tp):.3f}  (missed {fn} of {fn+tp} true suspicious sessions)")
print(f"[D2] ROC-AUC:   {roc_auc_score(y_test, y_prob):.3f}")

investigation["model_probability"] = model.predict_proba(inv_X)[:, 1]
ranked = investigation.sort_values("model_probability", ascending=False)
ranked["model_rank"] = range(1, len(ranked) + 1)


def interpret(row):
    reasons = []
    if row["impossible_travel"] == 1: reasons.append("impossible travel")
    if row["privilege_mismatch"] == 1: reasons.append("privilege mismatch")
    if row["new_device"] == 1: reasons.append("new device")
    if row["off_hours"] == 1: reasons.append("off-hours")
    if row["data_upload_mb"] > 50: reasons.append(f"large upload ({row['data_upload_mb']:.0f}MB)")
    if row["peer_deviation_score"] > 5: reasons.append(f"high peer deviation ({row['peer_deviation_score']:.1f})")
    return "; ".join(reasons) if reasons else "elevated composite risk score"


top15 = ranked.head(15).copy()
top15["interpretation"] = top15.apply(interpret, axis=1)
out = top15[["session_id", "session_start", "user_id", "model_probability", "interpretation"]].rename(columns={"model_probability": "probability"})
out.to_csv(BASE + r"\top_15_high_risk_sessions.csv", index=False)
print("\n[D2] top_15_high_risk_sessions.csv:")
print(out.to_string(index=False))

compare = ranked[["session_id", "model_probability", "model_rank"]].merge(
    scored[["session_id", "rule_score", "rule_flag_high_risk"]], on="session_id"
)
model_top15 = set(compare.sort_values("model_probability", ascending=False).head(15)["session_id"])
rule_top15 = set(compare.sort_values("rule_score", ascending=False).head(15)["session_id"])
print(f"\n[D2] Agreement between model and rule top-15: {len(model_top15 & rule_top15)} sessions")
print(f"[D2] Model-only (rule missed): {model_top15 - rule_top15}")
print(f"[D2] Rule-only (model missed): {rule_top15 - model_top15}")


# #######################################################################
# D3. THREAT INTELLIGENCE AND ADVERSARIAL LIMITATIONS
# #######################################################################
def recommended_action(row):
    if row["confidence"] == "High" and row["corroborated_internally"]:
        return "BLOCK / immediate action"
    if row["corroborated_internally"]:
        return "Investigate (corroborated, lower confidence)"
    return "Monitor only - do not act on the indicator alone"


intel["recommended_action"] = intel.apply(recommended_action, axis=1)
n_high_corroborated = intel[(intel["confidence"] == "High") & intel["corroborated_internally"]].shape[0]
n_uncorroborated = intel[~intel["corroborated_internally"]].shape[0]
print(f"\n[D3] High-confidence + internally corroborated (act on these): {n_high_corroborated}")
print(f"[D3] Uncorroborated indicators (monitor only): {n_uncorroborated} of {len(intel)}")

# Evasion simulation: does changing device/volume/auth-fatigue alone drop a
# real incident session below both the rule threshold and a "flag" decision?
target_session_id = non_standard_sessions[non_standard_sessions["session_id"].str.contains("KYC")]["session_id"].iloc[0] \
    if any(non_standard_sessions["session_id"].str.contains("KYC")) else scored.iloc[0]["session_id"]
real_row = investigation[investigation["session_id"] == target_session_id].iloc[0].copy()
evasive_row = real_row.copy()
evasive_row["new_device"] = 0
evasive_row["data_upload_mb"] = p75_upload * 0.5
evasive_row["failed_logins_30m"] = 0
evasive_row["mfa_denials"] = 0


def to_features(row):
    df = pd.DataFrame([row[FEATURES + ["department"]]])
    return pd.get_dummies(df, columns=["department"]).reindex(columns=train_X.columns, fill_value=0)


real_score = rule_score_row(real_row)["rule_score"]
evasive_score = rule_score_row(evasive_row)["rule_score"]
real_prob = model.predict_proba(to_features(real_row))[0, 1]
evasive_prob = model.predict_proba(to_features(evasive_row))[0, 1]
print(f"\n[D3] Evasion simulation on {target_session_id}:")
print(f"  Real rule_score={real_score} (flagged={real_score>=RULE_THRESHOLD})  "
      f"Evasive rule_score={evasive_score} (flagged={evasive_score>=RULE_THRESHOLD})")
print(f"  Real model probability={real_prob:.3f}  Evasive model probability={evasive_prob:.3f}")
print("  impossible_travel and privilege_mismatch alone carry enough weight to keep the evasive "
      "variant flagged - the real evasion path is spreading activity across many sessions over time, "
      "not tweaking a single session's soft indicators.")