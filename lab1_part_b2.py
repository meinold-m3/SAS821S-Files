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