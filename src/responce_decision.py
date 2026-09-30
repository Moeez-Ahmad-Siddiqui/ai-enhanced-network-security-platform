import pandas as pd

# Load evidence produced by threat hunting
evidence = pd.read_csv("high_risk_threat_evidence.csv")

print("\n========== AUTOMATED RESPONSE ENGINE ==========")

if evidence.empty:
    print("No high-risk evidence found.")
    print("ACTION: Continue monitoring")

else:
    # Get the highest UEBA score
    max_score = evidence["ueba_score"].max()

    print(f"Highest UEBA score: {max_score:.2f}")

    if max_score >= 70:
        decision = "QUARANTINE"
        reason = "High behavioral risk detected"

    elif max_score >= 40:
        decision = "INVESTIGATE"
        reason = "Medium behavioral risk detected"

    else:
        decision = "MONITOR"
        reason = "Low behavioral risk detected"

    print(f"DECISION: {decision}")
    print(f"REASON: {reason}")

    print("\nEntity requiring response:")
    print(evidence["id.orig_h"].iloc[0])

    # Create a simulated policy action
    policy = {
        "entity": evidence["id.orig_h"].iloc[0],
        "ueba_score": max_score,
        "decision": decision,
        "reason": reason
    }

    pd.DataFrame([policy]).to_csv(
        "dynamic_security_policy.csv",
        index=False
    )

    print("\nPolicy saved to: dynamic_security_policy.csv")

print("\n========== RESPONSE COMPLETE ==========")
