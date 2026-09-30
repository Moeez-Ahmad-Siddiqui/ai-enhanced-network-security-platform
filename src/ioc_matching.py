import pandas as pd

evidence = pd.read_csv("high_risk_threat_evidence.csv")
iocs = pd.read_csv("iocs.csv")

print("\n========== THREAT INTELLIGENCE / IOC MATCHING ==========")

ioc_ips = set(iocs["ioc"].astype(str))

matches = []

for _, row in evidence.iterrows():

    destination = str(row["id.resp_h"])

    if destination in ioc_ips:

        matches.append({
            "time": row["datetime"],
            "source": row["id.orig_h"],
            "destination": destination,
            "port": row["id.resp_p"],
            "ueba_score": row["ueba_score"],
            "ioc_match": "YES"
        })

if matches:

    results = pd.DataFrame(matches)

    print("\nIOC MATCHES FOUND:")
    print(results.to_string(index=False))

    results.to_csv(
        "ioc_matches.csv",
        index=False
    )

    print("\nIOC evidence saved to: ioc_matches.csv")

else:

    print("\nNo IOC matches found.")

print("\n========== IOC ANALYSIS COMPLETE ==========")
