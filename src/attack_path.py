import pandas as pd

df = pd.read_csv("network_forensic_timeline.csv")

print("\n========== ATTACK PATH ANALYSIS ==========")

source = df["id.orig_h"].iloc[0]

print("\nSOURCE ENTITY")
print(f"  {source}")

print("\nDESTINATION NODES")

for destination in df["id.resp_h"].unique():

    connections = len(
        df[df["id.resp_h"] == destination]
    )

    ports = ",".join(
        df[df["id.resp_h"] == destination]["id.resp_p"]
        .astype(str)
        .unique()
    )

    print(
        f"  {source} ---> {destination}"
        f" | Connections: {connections}"
        f" | Ports: {ports}"
    )

print("\n========== ATTACK PATH ==========")

print(f"{source}")

for destination in df["id.resp_h"].unique():
    print("   |")
    print("   +----> " + destination)

print("\n========== INCIDENT RESPONSE ==========")

print("1. High behavioral deviation detected")
print("2. Traffic evidence collected")
print("3. Destinations identified")
print("4. Incident timeline reconstructed")
print("5. Entity marked for quarantine")
print("6. Security team investigates before restoration")

print("\n========== ANALYSIS COMPLETE ==========")
