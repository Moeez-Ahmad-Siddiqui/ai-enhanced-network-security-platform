import pandas as pd

print("\n========== ENCRYPTED TRAFFIC ANALYSIS ==========")

fields = None

with open("ssl.log", "r") as file:
    for line in file:
        if line.startswith("#fields"):
            fields = line.strip().split("\t")[1:]
            break

if fields is None:
    print("ERROR: Could not find SSL fields")
    exit()

df = pd.read_csv(
    "ssl.log",
    sep="\t",
    comment="#",
    header=None,
    names=fields
)

print(f"\nTLS sessions analyzed: {len(df)}")

print("\n--- TLS VERSIONS ---")
print(df["version"].value_counts())

print("\n--- TLS CIPHERS ---")
print(df["cipher"].value_counts())

print("\n--- DESTINATION PORTS ---")
print(df["id.resp_p"].value_counts())

print("\n--- TLS CONNECTIONS ---")

for _, row in df.head(10).iterrows():
    print(
        f"{row['id.orig_h']} -> "
        f"{row['id.resp_h']}:{row['id.resp_p']} | "
        f"{row['version']} | "
        f"{row['cipher']} | "
        f"Curve: {row['curve']}"
    )

result = df[
    [
        "id.orig_h",
        "id.resp_h",
        "id.resp_p",
        "version",
        "cipher",
        "curve",
        "server_name",
        "resumed"
    ]
]

result.to_csv(
    "encrypted_traffic_analysis.csv",
    index=False
)

print("\nEncrypted traffic evidence saved to:")
print("encrypted_traffic_analysis.csv")

print("\n========== ENCRYPTED TRAFFIC ANALYSIS COMPLETE ==========")
