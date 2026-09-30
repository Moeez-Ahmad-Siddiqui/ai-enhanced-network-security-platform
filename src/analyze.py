import pandas as pd

print("Loading Zeek connection data...")

# Find the Zeek field names
fields = None

with open("conn.log", "r") as file:
    for line in file:
        if line.startswith("#fields"):
            fields = line.strip().split("\t")[1:]
            break

if fields is None:
    print("ERROR: Could not find #fields in conn.log")
    exit()

# Read the actual connection data
df = pd.read_csv(
    "conn.log",
    sep="\t",
    comment="#",
    header=None,
    names=fields
)

print("Data loaded successfully!")

print()
print("Number of connections:", len(df))

print()
print("Columns:")
print(df.columns.tolist())

print()
print("First 5 connections:")
print(df.head())

print()
print("========== PROTOCOLS ==========")
print(df["proto"].value_counts())

print()
print("========== DESTINATION PORTS ==========")
print(df["id.resp_p"].value_counts().head(10))

print()
print("========== TRAFFIC VOLUME ==========")

if "orig_bytes" in df.columns:
    orig_bytes = pd.to_numeric(
        df["orig_bytes"], errors="coerce"
    ).sum()

    print("Total bytes sent:", orig_bytes)

if "resp_bytes" in df.columns:
    resp_bytes = pd.to_numeric(
        df["resp_bytes"], errors="coerce"
    ).sum()

    print("Total bytes received:", resp_bytes)







print("\n========== BASIC BEHAVIORAL BASELINE ==========")

numeric_features = [
    "duration",
    "orig_bytes",
    "resp_bytes",
    "orig_pkts",
    "resp_pkts"
]

for feature in numeric_features:
    if feature in df.columns:

        values = pd.to_numeric(
            df[feature],
            errors="coerce"
        ).dropna()

        if len(values) > 0:
            print(f"\n{feature}")
            print("  Mean :", values.mean())
            print("  Min  :", values.min())
            print("  Max  :", values.max())
            print("  Std  :", values.std())




print("\n========== NETWORK BEHAVIORAL BASELINE ==========")

features = [
    "duration",
    "orig_bytes",
    "resp_bytes",
    "orig_pkts",
    "resp_pkts"
]

for feature in features:
    if feature in df.columns:

        values = pd.to_numeric(
            df[feature],
            errors="coerce"
        ).dropna()

        if len(values) > 0:

            print(f"\nFeature: {feature}")
            print(f"  Average : {values.mean():.2f}")
            print(f"  Minimum : {values.min():.2f}")
            print(f"  Maximum : {values.max():.2f}")
            print(f"  Std Dev : {values.std():.2f}")

print("\n========== PROTOCOL BASELINE ==========")

protocol_counts = df["proto"].value_counts()

print(protocol_counts)

print("\n========== PORT BASELINE ==========")

port_counts = df["id.resp_p"].value_counts()

print(port_counts)

