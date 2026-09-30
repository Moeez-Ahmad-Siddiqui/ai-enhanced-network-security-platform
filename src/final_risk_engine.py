import pandas as pd

# Load existing evidence
evidence = pd.read_csv("high_risk_threat_evidence.csv")
iocs = pd.read_csv("iocs.csv")

print("\n========== AI SECURITY RISK ENGINE ==========")

ioc_ips = set(iocs["ioc"].astype(str))

# Check IOC matches
evidence["ioc_match"] = evidence["id.resp_h"].astype(str).isin(ioc_ips)

# Get highest UEBA score
ueba_score = evidence["ueba_score"].max()

# Count IOC matches
ioc_count = evidence["ioc_match"].sum()

# Calculate IOC factor
ioc_factor = 100 if ioc_count > 0 else 0

# Combined risk score
combined_score = (ueba_score * 0.7) + (ioc_factor * 0.3)

print(f"UEBA Score: {ueba_score:.2f}")
print(f"IOC Matches: {ioc_count}")
print(f"IOC Risk Factor: {ioc_factor}")
print(f"Combined Risk Score: {combined_score:.2f}")

# Final decision
if combined_score >= 70:
    risk = "HIGH"
    action = "QUARANTINE"

elif combined_score >= 40:
    risk = "MEDIUM"
    action = "INVESTIGATE"

else:
    risk = "LOW"
    action = "MONITOR"

print("\n========== FINAL SECURITY DECISION ==========")
print(f"Risk Level: {risk}")
print(f"Recommended Action: {action}")

if action == "QUARANTINE":
    print("\nDynamic Policy:")
    print("BLOCK network access")
    print("PLACE entity into quarantine segment")
    print("ALLOW security monitoring")
    print("REQUIRE investigation before restoration")

elif action == "INVESTIGATE":
    print("\nDynamic Policy:")
    print("RESTRICT suspicious activity")
    print("CONTINUE monitoring")

else:
    print("\nDynamic Policy:")
    print("ALLOW normal activity")

# Save final decision
result = pd.DataFrame([{
    "entity": evidence["id.orig_h"].iloc[0],
    "ueba_score": ueba_score,
    "ioc_matches": ioc_count,
    "combined_score": combined_score,
    "risk_level": risk,
    "recommended_action": action
}])

result.to_csv(
    "final_security_decision.csv",
    index=False
)

print("\nFinal decision saved to: final_security_decision.csv")
print("\n========== RISK ENGINE COMPLETE ==========")
