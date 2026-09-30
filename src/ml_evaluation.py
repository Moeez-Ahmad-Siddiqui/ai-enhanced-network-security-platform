import pandas as pd
import numpy as np

from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)
from sklearn.model_selection import train_test_split


print("========== CONTROLLED ML EVALUATION ==========")

# -------------------------------------------------
# 1. LOAD ZEEK DATA
# -------------------------------------------------

fields = None

with open("conn.log", "r") as file:
    for line in file:
        if line.startswith("#fields"):
            fields = line.strip().split("\t")[1:]
            break

if fields is None:
    print("ERROR: Could not find #fields in conn.log")
    exit()

df = pd.read_csv(
    "conn.log",
    sep="\t",
    comment="#",
    header=None,
    names=fields
)

print("Connections loaded:", len(df))


# -------------------------------------------------
# 2. SAME FEATURES AS PRODUCTION MODEL
# -------------------------------------------------

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

df["proto"] = df["proto"].fillna("unknown")

protocol_features = pd.get_dummies(
    df["proto"],
    prefix="proto"
)

X = pd.concat(
    [
        df[numeric_features],
        protocol_features
    ],
    axis=1
)

X = X.apply(
    pd.to_numeric,
    errors="coerce"
)

X = X.fillna(0)


# -------------------------------------------------
# 3. TRAIN / TEST SPLIT
# -------------------------------------------------

X_train, X_test = train_test_split(
    X,
    test_size=0.30,
    random_state=42
)

print("Training baseline samples:", len(X_train))
print("Testing baseline samples:", len(X_test))


# -------------------------------------------------
# 4. TRAIN ISOLATION FOREST
# -------------------------------------------------

model = IsolationForest(
    contamination=0.05,
    random_state=42
)

model.fit(X_train)

print("Isolation Forest training complete.")


# -------------------------------------------------
# 5. CREATE CONTROLLED ANOMALIES
# -------------------------------------------------

rng = np.random.default_rng(42)

# Use part of the test data as a controlled anomaly set
anomaly_count = min(100, len(X_test))

normal_test = X_test.iloc[:anomaly_count].copy()
anomalies = normal_test.copy()

# Create deliberately unusual traffic behaviour
for feature in [
    "duration",
    "orig_bytes",
    "resp_bytes",
    "orig_pkts",
    "resp_pkts"
]:
    if feature in anomalies.columns:
        anomalies[feature] = (
            anomalies[feature] * 50 + 1000
        )

# Force unusual destination port
anomalies["id.resp_p"] = 65000

# Add small random variation
anomalies = anomalies + rng.normal(
    0,
    0.01,
    size=anomalies.shape
)

# Restore port value
anomalies["id.resp_p"] = 65000


# -------------------------------------------------
# 6. BUILD LABORATORY TEST DATA
# -------------------------------------------------

evaluation_data = pd.concat(
    [
        normal_test,
        anomalies
    ],
    ignore_index=True
)

# Ground truth:
# 0 = Normal
# 1 = Controlled anomaly

y_true = np.array(
    [0] * len(normal_test) +
    [1] * len(anomalies)
)


# -------------------------------------------------
# 7. MODEL PREDICTION
# -------------------------------------------------

model_predictions = model.predict(
    evaluation_data
)

# Isolation Forest:
# +1 = normal
# -1 = anomaly

y_pred = np.where(
    model_predictions == -1,
    1,
    0
)


# -------------------------------------------------
# 8. EVALUATION METRICS
# -------------------------------------------------

accuracy = accuracy_score(
    y_true,
    y_pred
)

precision = precision_score(
    y_true,
    y_pred,
    zero_division=0
)

recall = recall_score(
    y_true,
    y_pred,
    zero_division=0
)

f1 = f1_score(
    y_true,
    y_pred,
    zero_division=0
)

cm = confusion_matrix(
    y_true,
    y_pred
)


print("\n========== EVALUATION RESULTS ==========")

print(f"Accuracy :  {accuracy:.4f}")
print(f"Precision:  {precision:.4f}")
print(f"Recall   :  {recall:.4f}")
print(f"F1 Score :  {f1:.4f}")

print("\n========== CONFUSION MATRIX ==========")
print(cm)

print("\n========== CLASSIFICATION REPORT ==========")

print(
    classification_report(
        y_true,
        y_pred,
        target_names=["Normal", "Anomaly"],
        zero_division=0
    )
)


# -------------------------------------------------
# 9. SAVE RESULTS
# -------------------------------------------------

results = pd.DataFrame({
    "metric": [
        "Accuracy",
        "Precision",
        "Recall",
        "F1 Score"
    ],
    "value": [
        accuracy,
        precision,
        recall,
        f1
    ]
})

results.to_csv(
    "ml_evaluation_results.csv",
    index=False
)

print("\nResults saved to: ml_evaluation_results.csv")
print("\n========== EVALUATION COMPLETE ==========")
