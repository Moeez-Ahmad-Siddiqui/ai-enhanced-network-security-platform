import pandas as pd
from datetime import datetime

print("\n")
print("======================================================")
print("     AI-ENHANCED NETWORK SECURITY PLATFORM")
print("        AUTOMATED INCIDENT RESPONSE ENGINE")
print("======================================================")

# ------------------------------------------------------
# 1. LOAD SECURITY EVIDENCE
# ------------------------------------------------------

decision = pd.read_csv("final_security_decision.csv")
forensics = pd.read_csv("network_forensic_timeline.csv")
ioc = pd.read_csv("ioc_matches.csv")

entity = decision["entity"].iloc[0]
ueba_score = decision["ueba_score"].iloc[0]
ioc_matches = decision["ioc_matches"].iloc[0]
combined_score = decision["combined_score"].iloc[0]
risk_level = decision["risk_level"].iloc[0]
action = decision["recommended_action"].iloc[0]

print("\n--- 1. SECURITY ASSESSMENT ---")

print(f"Entity: {entity}")
print(f"UEBA Score: {ueba_score:.2f}")
print(f"IOC Matches: {ioc_matches}")
print(f"Combined Risk Score: {combined_score:.2f}")
print(f"Risk Level: {risk_level}")
print(f"Recommended Action: {action}")

# ------------------------------------------------------
# 2. DPI ANALYSIS
# ------------------------------------------------------

print("\n--- 2. NETWORK TRAFFIC ANALYSIS ---")

dpi = pd.read_csv("dpi_protocol_analysis.csv")

for _, row in dpi.iterrows():
    print(
        f"Protocol: {row['protocol']} "
        f"| Connections: {row['connections']}"
    )

# ------------------------------------------------------
# 3. ENCRYPTED TRAFFIC
# ------------------------------------------------------

print("\n--- 3. ENCRYPTED TRAFFIC ANALYSIS ---")

tls = pd.read_csv("encrypted_traffic_analysis.csv")

print(f"TLS Sessions: {len(tls)}")

tls_versions = tls["version"].value_counts()

for version, count in tls_versions.items():
    print(f"{version}: {count}")

# ------------------------------------------------------
# 4. IOC EVIDENCE
# ------------------------------------------------------

print("\n--- 4. THREAT INTELLIGENCE CORRELATION ---")

print(f"IOC matches found: {len(ioc)}")

for _, row in ioc.iterrows():
    print(
        f"{row['source']} -> {row['destination']}:{row['port']} "
        f"| IOC MATCH"
    )

# ------------------------------------------------------
# 5. FORENSIC INVESTIGATION
# ------------------------------------------------------

print("\n--- 5. NETWORK FORENSICS ---")

print(f"Evidence records: {len(forensics)}")

if "source" in forensics.columns:
    print(f"Source entity: {forensics['source'].iloc[0]}")

if "destination" in forensics.columns:
    destinations = forensics["destination"].nunique()
    print(f"Unique destinations: {destinations}")

# ------------------------------------------------------
# 6. AUTOMATED RESPONSE
# ------------------------------------------------------

print("\n--- 6. AUTOMATED RESPONSE ---")

if action == "QUARANTINE":

    print("ACTION: QUARANTINE")
    print("BLOCK network access")
    print("PLACE entity into quarantine segment")
    print("ALLOW security monitoring")
    print("REQUIRE investigation before restoration")

elif action == "INVESTIGATE":

    print("ACTION: INVESTIGATE")
    print("RESTRICT suspicious activity")
    print("CONTINUE monitoring")

else:

    print("ACTION: MONITOR")
    print("ALLOW normal activity")
    print("CONTINUE monitoring")

# ------------------------------------------------------
# 7. INCIDENT REPORT
# ------------------------------------------------------

report = pd.DataFrame([{
    "timestamp": datetime.now(),
    "entity": entity,
    "ueba_score": ueba_score,
    "ioc_matches": ioc_matches,
    "combined_risk_score": combined_score,
    "risk_level": risk_level,
    "recommended_action": action,
    "tls_sessions": len(tls),
    "forensic_records": len(forensics)
}])

report.to_csv(
    "automated_incident_report.csv",
    index=False
)

print("\n--- 7. INCIDENT REPORT ---")

print("Automated incident report generated:")
print("automated_incident_report.csv")

print("\n======================================================")
print("       INCIDENT RESPONSE WORKFLOW COMPLETE")
print("======================================================")
