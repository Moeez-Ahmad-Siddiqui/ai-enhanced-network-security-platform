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
# 3. Convert timestamp
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
# 4. Create 1-minute behavior windows
# --------------------------------------------------

df["time_window"] = df["datetime"].dt.floor("1min")

# --------------------------------------------------
# 5. Convert traffic fields to numbers
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
# 6. Build entity behavior profiles
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

print("\n========== UEBA ENTITY BEHAVIOR ==========")

print(
    entity_behavior.to_string(index=False)
)

# --------------------------------------------------
# 7. Define behavioral features
# --------------------------------------------------

behavior_features = [
    "connections",
    "total_sent",
    "total_received",
    "total_orig_pkts",
    "total_resp_pkts"
]

# --------------------------------------------------
# 8. Sort windows chronologically
# --------------------------------------------------

entity_behavior = entity_behavior.sort_values(
    ["id.orig_h", "time_window"]
).reset_index(drop=True)

# --------------------------------------------------
# 9. Build historical baseline
# --------------------------------------------------

# Each window is compared with previous
# observations from the same entity.

results = []

for entity, group in entity_behavior.groupby("id.orig_h"):

    group = group.copy()

    for i in range(len(group)):

        current = group.iloc[i]

        # Need at least 3 previous windows
        # to establish a baseline.
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

            # Prevent division by zero
            std = std.replace(0, 1)

            z_scores = (
                (
                    current[behavior_features]
                    - baseline
                ) / std
            ).abs()

            deviation = z_scores.mean()

            # Convert deviation to 0-100
            # relative to a practical threshold.
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
            "ueba_deviation"
        ] = deviation

        group.loc[
            group.index[i],
            "ueba_score"
        ] = score

        group.loc[
            group.index[i],
            "ueba_risk"
        ] = risk

    results.append(group)

# Combine all entities

entity_behavior = pd.concat(
    results,
    ignore_index=True
)

# --------------------------------------------------
# 10. Display results
# --------------------------------------------------

print("\n========== UEBA HISTORICAL BASELINE RESULTS ==========")

print(
    entity_behavior[
        [
            "id.orig_h",
            "time_window",
            "connections",
            "total_sent",
            "total_received",
            "total_orig_pkts",
            "total_resp_pkts",
            "ueba_deviation",
            "ueba_score",
            "ueba_risk"
        ]
    ].to_string(index=False)
)

print("\n========== UEBA COMPLETE ==========")
