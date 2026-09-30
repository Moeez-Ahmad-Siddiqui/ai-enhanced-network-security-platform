import pandas as pd
from sklearn.ensemble import IsolationForest

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
# 3. Select numeric features
# --------------------------------------------------

numeric_features = [
    "duration",
    "orig_bytes",
    "resp_bytes",
    "orig_pkts",
    "resp_pkts",
    "id.resp_p"
]

for feature in numeric_features:
    df[feature] = pd.to_numeric(
        df[feature],
        errors="coerce"
    )

# --------------------------------------------------
# 4. Select protocol
# --------------------------------------------------

df["proto"] = df["proto"].fillna("unknown")

# One-hot encode protocol
protocol_features = pd.get_dummies(
    df["proto"],
    prefix="proto"
)

# --------------------------------------------------
# 5. Combine features
# --------------------------------------------------

X = pd.concat(
    [
        df[numeric_features],
        protocol_features
    ],
    axis=1
)

# Convert everything to numeric
X = X.apply(
    pd.to_numeric,
    errors="coerce"
)

# Replace missing values
X = X.fillna(0)

print("\n========== ML FEATURES ==========")

print(X.columns.tolist())

# --------------------------------------------------
# 6. Create Isolation Forest
# --------------------------------------------------

model = IsolationForest(
    contamination=0.05,
    random_state=42
)

# --------------------------------------------------
# 7. Train
# --------------------------------------------------

model.fit(X)

# --------------------------------------------------
# 8. Predict
# --------------------------------------------------

df["anomaly"] = model.predict(X)

df["status"] = df["anomaly"].map({
    1: "Normal",
    -1: "Anomaly"
})

df["anomaly_score"] = model.decision_function(X)

df["unusualness"] = -df["anomaly_score"]

df["risk_score"] = (
    (df["unusualness"] - df["unusualness"].min())
    /
    (df["unusualness"].max() - df["unusualness"].min())
    * 100
)

df["risk_level"] = pd.cut(
    df["risk_score"],
    bins=[-1, 39, 69, 100],
    labels=["Low", "Medium", "High"]
)
# --------------------------------------------------
# 9. Results
# --------------------------------------------------

print("\n========== RESULTS ==========")

print(df["status"].value_counts())

# --------------------------------------------------
# 10. Display anomalies
# --------------------------------------------------

print("\n========== DETECTED ANOMALIES ==========")

anomalies = df[
    df["status"] == "Anomaly"
].sort_values(
    by="risk_score",
    ascending=False
)

print(
    anomalies[
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
            "unusualness",
            "risk_score",
            "risk_level",
            "status"
        ]
    ].to_string(index=False)
)

