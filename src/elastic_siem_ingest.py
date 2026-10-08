import pandas as pd
from elasticsearch import Elasticsearch

# Elasticsearch configuration
ES_URL = "https://localhost:9200"
INDEX = "ai-network-security"

# IMPORTANT:
# Replace YOUR_PASSWORD with your Elasticsearch 'elastic' user password.
es = Elasticsearch(
    ES_URL,
    basic_auth=("elastic", "0MpyhX77wyLl9ksSa3G5"),
    verify_certs=False
)

# Load the final AI security decision
df = pd.read_csv("final_security_decision.csv")

# Send each security decision to Elasticsearch
for _, row in df.iterrows():

    event = {
        "@timestamp": pd.Timestamp.now(tz="UTC").isoformat(),
        "entity": str(row["entity"]),
        "ueba_score": float(row["ueba_score"]),
        "ioc_matches": int(row["ioc_matches"]),
        "combined_risk": float(row["combined_score"]),
        "risk_level": str(row["risk_level"]),
        "recommended_action": str(row["recommended_action"]),
        "source": "AI Network Security Platform",
        "environment": "Controlled Laboratory"
    }

    # Stable ID prevents duplicate documents
    doc_id = f"{event['entity']}-{event['recommended_action']}"

    es.index(
        index=INDEX,
        id=doc_id,
        document=event
    )

print(f"Successfully ingested {len(df)} security event(s) into Elasticsearch.")


