import pandas as pd

print("\n========== DPI / APPLICATION ANALYSIS ==========")

fields = None

with open("conn.log", "r") as file:
    for line in file:
        if line.startswith("#fields"):
            fields = line.strip().split("\t")[1:]
            break

if fields is None:
    print("ERROR: Could not find #fields")
    exit()

df = pd.read_csv(
    "conn.log",
    sep="\t",
    comment="#",
    header=None,
    names=fields
)

# Count protocols
protocols = df["proto"].value_counts()

print("\n--- NETWORK PROTOCOLS ---")

for protocol, count in protocols.items():
    print(f"{protocol}: {count} connections")

# Count application/service identification
services = df["service"].replace("-", "Unknown").value_counts()

print("\n--- APPLICATION / SERVICE IDENTIFICATION ---")

for service, count in services.items():
    print(f"{service}: {count} connections")

# Destination ports
ports = df["id.resp_p"].value_counts().head(10)

print("\n--- TOP DESTINATION PORTS ---")

for port, count in ports.items():
    print(f"Port {port}: {count} connections")

# Save results
result = pd.DataFrame({
    "protocol": protocols.index,
    "connections": protocols.values
})

result.to_csv(
    "dpi_protocol_analysis.csv",
    index=False
)

print("\nDPI analysis saved to: dpi_protocol_analysis.csv")

print("\n========== DPI ANALYSIS COMPLETE ==========")
