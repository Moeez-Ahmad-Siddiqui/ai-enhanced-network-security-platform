import pandas as pd
from sklearn.ensemble import IsolationForest

print("Loading Zeek data...")

# Read Zeek field names
fields = None

with open("conn.log", "r") as file:
    for line in file:
        if line.startswith("#fields"):
            fields = line.strip().split("\t")[1:]
            break

if fields is None:
    print("ERROR: Could not find #fields")
    exit()

# Load connection data
df = pd.read_csv(
    "conn.log",
    sep="\t",
    comment="#",
    header=None,
    names=fields
)

print("Connections loaded:", len(df))

# Features used by the ML model
features = [
    "duration",
    "orig_bytes",
    "resp_bytes",
    "orig_pkts",
    "resp_pkts"
]

# Convert features to numbers
for feature in features:
    df[feature] = pd.to_numeric(
        df[feature],
        errors="coerce"
    )

# Replace missing values with 0
df[features] = df[features].fillna(0)

print("\nFeatures used by the model:")
print(features)

# Create Isolation Forest model
model = IsolationForest(
    contamination=0.05,
    random_state=42
)

# Train model
model.fit(df[features])

# Predict
df["anomaly"] = model.predict(df[features])

# Convert result to readable labels
df["status"] = df["anomaly"].map({
    1: "Normal",
    -1: "Anomaly"
})

print("\n========== RESULTS ==========")

print(df["status"].value_counts())

print("\n========== SUSPICIOUS CONNECTIONS ==========")

suspicious = df[df["status"] == "Anomaly"]

print(
    suspicious[
        [
            "id.orig_h",
            "id.resp_h",
            "id.resp_p",
            "proto",
            "duration",
            "orig_bytes",
            "resp_bytes",
            "orig_pkts",
            "resp_pkts",
            "status"
        ]
    ].to_string(index=False)
)

