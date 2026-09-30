import pandas as pd

print("Loading Zeek data...")

# --------------------------------------------------
# 1. Read Zeek field names
# --------------------------------------------------

fields = None

with open("conn.log", "r") as file:
    for line in file:
        if line.startswith("#fields"):
            fields = line.strip().split("\t")[1:]
            break

if fields is None:
    print("ERROR: Could not find #fields")
    exit()

# --------------------------------------------------
# 2. Load Zeek connection data
# --------------------------------------------------

df = pd.read_csv(
    "conn.log",
    sep="\t",
    comment="#",
    header=None,
    names=fields
)

print("Connections loaded:", len(df))

# --------------------------------------------------
# 3. Convert timestamps
# --------------------------------------------------

df["ts"] = pd.to_numeric(
    df["ts"],
    errors="coerce"
)

df["datetime"] = pd.to_datetime(
    df["ts"],
    unit="s"
)

# --------------------------------------------------
# 4. Create 1-minute windows
# --------------------------------------------------

df["time_window"] = df["datetime"].dt.floor("1min")

# --------------------------------------------------
# 5. Convert traffic fields
# --------------------------------------------------

numeric_features = [
    "orig_ip_bytes",
    "resp_ip_bytes",
    "orig_pkts",
    "resp_pkts",
    "duration"
]

for feature in numeric_features:
    df[feature] = pd.to_numeric(
        df[feature],
        errors="coerce"
    )

df[numeric_features] = df[numeric_features].fillna(0)

# --------------------------------------------------
# 6. Find high-activity windows
# --------------------------------------------------

window_activity = df.groupby(
    ["id.orig_h", "time_window"]
).agg(
    connections=("id.orig_h", "count"),
    total_sent=("orig_ip_bytes", "sum"),
    total_received=("resp_ip_bytes", "sum")
).reset_index()

# --------------------------------------------------
# 7. Detect suspicious behavior
# --------------------------------------------------

# For this laboratory demonstration,
# a window with unusually high connection
# activity is selected for investigation.

connection_threshold = 20

suspicious_windows = window_activity[
    window_activity["connections"] >= connection_threshold
]

print("\n========== THREAT HUNTING ==========")

if suspicious_windows.empty:

    print("No suspicious activity detected.")

else:

    print("\nSuspicious behavioral windows:")

    print(
        suspicious_windows.to_string(
            index=False
        )
    )

# --------------------------------------------------
# 8. Investigate suspicious connections
# --------------------------------------------------

if not suspicious_windows.empty:

    evidence = df.merge(
        suspicious_windows[
            ["id.orig_h", "time_window"]
        ],
        on=["id.orig_h", "time_window"],
        how="inner"
    )

    evidence = evidence[
        [
            "datetime",
            "id.orig_h",
            "id.resp_h",
            "id.resp_p",
            "proto",
            "service",
            "conn_state",
            "duration",
            "orig_ip_bytes",
            "resp_ip_bytes",
            "orig_pkts",
            "resp_pkts"
        ]
    ]

    print("\n========== INVESTIGATION EVIDENCE ==========")

    print(
        evidence.to_string(index=False)
    )

    # --------------------------------------------------
    # 9. Save evidence
    # --------------------------------------------------

    evidence.to_csv(
        "threat_hunting_evidence.csv",
        index=False
    )

    print(
        "\nEvidence saved to:"
        " threat_hunting_evidence.csv"
    )

print("\n========== THREAT HUNTING COMPLETE ==========")
