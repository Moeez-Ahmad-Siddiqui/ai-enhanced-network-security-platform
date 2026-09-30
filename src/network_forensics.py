import pandas as pd

print("\n========== NETWORK FORENSICS ==========")

# Load high-risk evidence
df = pd.read_csv("high_risk_threat_evidence.csv")

# Convert timestamp
df["datetime"] = pd.to_datetime(df["datetime"])

# Sort chronologically
df = df.sort_values("datetime")

print("\n--- INCIDENT TIMELINE ---")

for _, row in df.iterrows():

    print(
        f"{row['datetime']} | "
        f"{row['id.orig_h']} -> "
        f"{row['id.resp_h']}:{row['id.resp_p']} | "
        f"{row['proto']} | "
        f"State: {row['conn_state']}"
    )

# Incident summary
source = df["id.orig_h"].iloc[0]

start_time = df["datetime"].min()
end_time = df["datetime"].max()

unique_destinations = df["id.resp_h"].nunique()
total_connections = len(df)

print("\n--- INCIDENT SUMMARY ---")
print(f"Source entity: {source}")
print(f"Start time: {start_time}")
print(f"End time: {end_time}")
print(f"Connections investigated: {total_connections}")
print(f"Unique destinations: {unique_destinations}")

# Save forensic report
df.to_csv("network_forensic_timeline.csv", index=False)

print("\nForensic timeline saved to:")
print("network_forensic_timeline.csv")

print("\n========== FORENSICS COMPLETE ==========")
