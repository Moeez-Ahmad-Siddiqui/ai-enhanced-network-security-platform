import pandas as pd

policy = pd.read_csv("dynamic_security_policy.csv")

print("\n========== DYNAMIC POLICY ENFORCEMENT ==========")

for _, row in policy.iterrows():

    entity = row["entity"]
    score = row["ueba_score"]
    decision = row["decision"]

    print(f"Entity: {entity}")
    print(f"Risk Score: {score:.2f}")
    print(f"Policy Decision: {decision}")

    if decision == "QUARANTINE":

        print("\n[SDN POLICY]")
        print(f"BLOCK network access for {entity}")
        print(f"PLACE {entity} into QUARANTINE segment")
        print("ALLOW security-monitoring traffic")
        print("REQUIRE investigation before restoration")

    elif decision == "INVESTIGATE":

        print("\n[SDN POLICY]")
        print(f"RESTRICT {entity}")
        print("CONTINUE monitoring")

    else:

        print("\n[SDN POLICY]")
        print(f"ALLOW normal access for {entity}")

print("\n========== ENFORCEMENT COMPLETE ==========")
