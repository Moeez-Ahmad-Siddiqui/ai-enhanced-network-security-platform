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
# 2. Load Zeek data
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
# 3. Prepare timestamps
# --------------------------------------------------

df["ts"] = pd.to_numeric(
    df["ts"],
    errors="coerce"
)

df["datetime"] = pd.to_datetime(
    df["ts"],
    unit="s"
)

df["time_window"] = df["datetime"].dt.floor("1min")

# --------------------------------------------------
# 4. Convert traffic fields
# --------------------------------------------------

numeric_features = [
    "orig_ip_bytes",
    "resp_ip_bytes",
    "orig_pkts",
    "resp_pkts"
]

for feature in numeric_features:
    df[feature] = pd.to_numeric(
        df[feature],
        errors="coerce"
    )

df[numeric_features] = df[numeric_features].fillna(0)

# --------------------------------------------------
# 5. Build UEBA behavior
# --------------------------------------------------

entity_behavior = df.groupby(
    ["id.orig_h", "time_window"]
).agg(
    connections=("id.orig_h", "count"),
    total_sent=("orig_ip_bytes", "sum"),
    total_received=("resp_ip_bytes", "sum"),
    total_orig_pkts=("orig_pkts", "sum"),
    total_resp_pkts=("resp_pkts", "sum")
).reset_index()

behavior_features = [
    "connections",
    "total_sent",
    "total_received",
    "total_orig_pkts",
    "total_resp_pkts"
]

entity_behavior = entity_behavior.sort_values(
    ["id.orig_h", "time_window"]
).reset_index(drop=True)

# --------------------------------------------------
# 6. Historical UEBA baseline
# --------------------------------------------------

results = []

for entity, group in entity_behavior.groupby("id.orig_h"):

    group = group.copy()

    for i in range(len(group)):

        current = group.iloc[i]

        # First 3 windows establish baseline
        if i < 3:

            deviation = 0
            score = 0
            risk = "Baseline"

        else:

            history = group.iloc[:i]

            baseline = history[
                behavior_features
            ].mean()

            std = history[
                behavior_features
            ].std()

            std = std.replace(0, 1)

            z_scores = (
                (
                    current[behavior_features]
                    - baseline
                ) / std
            ).abs()

            deviation = z_scores.mean()

            score = min(
                deviation / 3 * 100,
                100
            )

            if score < 40:
                risk = "Low"

            elif score < 70:
                risk = "Medium"

            else:
                risk = "High"

        group.loc[
            group.index[i],
            "ueba_score"
        ] = score

        group.loc[
            group.index[i],
            "ueba_risk"
        ] = risk

    results.append(group)

entity_behavior = pd.concat(
    results,
    ignore_index=True
)

# --------------------------------------------------
# 7. AUTOMATED THREAT HUNTING
# --------------------------------------------------

print("\n========== UEBA RESULTS ==========")

print(
    entity_behavior[
        [
            "id.orig_h",
            "time_window",
            "connections",
            "ueba_score",
            "ueba_risk"
        ]
    ].to_string(index=False)
)

# --------------------------------------------------
# 8. Select HIGH-risk windows
# --------------------------------------------------

high_risk = entity_behavior[
    entity_behavior["ueba_risk"] == "High"
]

print("\n========== AUTOMATED THREAT HUNTING ==========")

if high_risk.empty:

    print("No HIGH-risk behavioral activity detected.")

else:

    print(
        "HIGH-risk activity detected."
    )

    print(
        high_risk[
            [
                "id.orig_h",
                "time_window",
                "connections",
                "ueba_score",
                "ueba_risk"
            ]
        ].to_string(index=False)
    )

# --------------------------------------------------
# 9. Investigate HIGH-risk windows
# --------------------------------------------------

if not high_risk.empty:

    evidence = df.merge(
        high_risk[
            [
                "id.orig_h",
                "time_window",
                "ueba_score",
                "ueba_risk"
            ]
        ],
        on=[
            "id.orig_h",
            "time_window"
        ],
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
            "resp_pkts",
            "ueba_score",
            "ueba_risk"
        ]
    ]

    # Sort evidence chronologically

    evidence = evidence.sort_values(
        "datetime"
    )

    print(
        "\n========== HIGH-RISK INVESTIGATION EVIDENCE =========="
    )

    print(
        evidence.to_string(index=False)
    )

    # --------------------------------------------------
    # 10. Save evidence
    # --------------------------------------------------

    evidence.to_csv(
        "high_risk_threat_evidence.csv",
        index=False
    )

    print(
        "\nEvidence saved to:"
        " high_risk_threat_evidence.csv"
    )

# --------------------------------------------------
# 11. Automated response decision
# --------------------------------------------------

print(
    "\n========== SECURITY DECISION =========="
)

if high_risk.empty:

    print("ACTION: Continue monitoring")

else:

    print(
        "ACTION: Investigate HIGH-risk entity"
    )

    print(
        "NEXT STEP: Consider containment/quarantine"
    )

print("\n========== THREAT HUNTING COMPLETE ==========")
