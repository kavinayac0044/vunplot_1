import os
import json
import requests
import pandas as pd


# ============================================================
# Configuration
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

INPUT_PATH = os.path.join(
    BASE_DIR,
    "data",
    "raw",
    "nvd_recent_cves.json"
)

OUTPUT_PATH = os.path.join(
    BASE_DIR,
    "data",
    "processed",
    "phase1_experimental_sample.csv"
)

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/"
    "feeds/known_exploited_vulnerabilities.json"
)

TOTAL_SAMPLE_SIZE = 3000

RANDOM_STATE = 42


# ============================================================
# Load NVD
# ============================================================

print("=" * 70)
print("VulnPilot-X - Phase 1 Experimental Sampling")
print("=" * 70)

with open(
    INPUT_PATH,
    "r",
    encoding="utf-8"
) as f:

    nvd_data = json.load(f)


records = nvd_data.get(
    "vulnerabilities",
    []
)

print(
    f"\nNVD records loaded: {len(records)}"
)


# ============================================================
# Extract CVE information
# ============================================================

rows = []

for item in records:

    cve = item.get(
        "cve",
        {}
    )

    cve_id = cve.get(
        "id"
    )

    if not cve_id:
        continue

    descriptions = cve.get(
        "descriptions",
        []
    )

    description = ""

    for desc in descriptions:

        if desc.get("lang") == "en":

            description = desc.get(
                "value",
                ""
            )

            break

    metrics = cve.get(
        "metrics",
        {}
    )

    # --------------------------------------------------------
    # Determine whether CVSS exists
    # --------------------------------------------------------

    cvss_data = None
    cvss_version = None

    # Prefer CVSS 4.0
    if metrics.get("cvssMetricV40"):

        metric = metrics["cvssMetricV40"][0]

        cvss_data = metric.get(
            "cvssData",
            {}
        )

        cvss_version = "4.0"

    # Then CVSS 3.1
    elif metrics.get("cvssMetricV31"):

        metric = metrics["cvssMetricV31"][0]

        cvss_data = metric.get(
            "cvssData",
            {}
        )

        cvss_version = "3.1"

    # Then CVSS 3.0
    elif metrics.get("cvssMetricV30"):

        metric = metrics["cvssMetricV30"][0]

        cvss_data = metric.get(
            "cvssData",
            {}
        )

        cvss_version = "3.0"

    # Then CVSS 2.0
    elif metrics.get("cvssMetricV2"):

        metric = metrics["cvssMetricV2"][0]

        cvss_data = metric.get(
            "cvssData",
            {}
        )

        cvss_version = "2.0"

    if not cvss_data:
        continue

    cvss_score = cvss_data.get(
        "baseScore"
    )

    if cvss_score is None:
        continue

    rows.append(
        {
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "cvss_version": cvss_version,
            "published": cve.get(
                "published"
            ),
            "last_modified": cve.get(
                "lastModified"
            )
        }
    )


df = pd.DataFrame(rows)

print(
    f"CVEs with CVSS: {len(df)}"
)


# ============================================================
# Download KEV
# ============================================================

print(
    "\nDownloading CISA KEV catalog..."
)

response = requests.get(
    KEV_URL,
    timeout=60
)

response.raise_for_status()

kev_data = response.json()

kev_records = kev_data.get(
    "vulnerabilities",
    []
)

kev_cves = {
    item.get("cveID")
    for item in kev_records
    if item.get("cveID")
}


# ============================================================
# Add KEV status
# ============================================================

df["kev_status"] = (
    df["cve_id"]
    .isin(kev_cves)
    .astype(int)
)


# ============================================================
# Split KEV / non-KEV
# ============================================================

kev_df = df[
    df["kev_status"] == 1
].copy()

non_kev_df = df[
    df["kev_status"] == 0
].copy()


print(
    f"\nCVSS + KEV records     : {len(kev_df)}"
)

print(
    f"CVSS + non-KEV records: {len(non_kev_df)}"
)


# ============================================================
# Keep all KEV records
# ============================================================

if len(kev_df) > TOTAL_SAMPLE_SIZE:

    raise ValueError(
        "Number of KEV records exceeds the requested "
        "experimental sample size."
    )


non_kev_needed = (
    TOTAL_SAMPLE_SIZE
    - len(kev_df)
)


if len(non_kev_df) < non_kev_needed:

    raise ValueError(
        "Not enough non-KEV records available."
    )


# ============================================================
# Reproducible random sampling
# ============================================================

non_kev_sample = non_kev_df.sample(
    n=non_kev_needed,
    random_state=RANDOM_STATE
)


sample = pd.concat(
    [
        kev_df,
        non_kev_sample
    ],
    ignore_index=True
)


# Shuffle final dataset

sample = sample.sample(
    frac=1,
    random_state=RANDOM_STATE
).reset_index(
    drop=True
)


# ============================================================
# Save
# ============================================================

os.makedirs(
    os.path.dirname(OUTPUT_PATH),
    exist_ok=True
)

sample.to_csv(
    OUTPUT_PATH,
    index=False,
    encoding="utf-8"
)


# ============================================================
# Summary
# ============================================================

print("\n" + "=" * 70)
print("PHASE 1 SAMPLE CREATED")
print("=" * 70)

print(
    f"\nTotal sample       : {len(sample)}"
)

print(
    f"KEV records        : "
    f"{sample['kev_status'].sum()}"
)

print(
    f"Non-KEV records    : "
    f"{(sample['kev_status'] == 0).sum()}"
)

print(
    f"KEV proportion     : "
    f"{sample['kev_status'].mean() * 100:.2f}%"
)

print(
    f"\nRandom state       : {RANDOM_STATE}"
)

print(
    f"\nSaved to:\n{OUTPUT_PATH}"
)


# ============================================================
# CVSS version distribution
# ============================================================

print(
    "\nCVSS version distribution:"
)

print(
    sample[
        "cvss_version"
    ].value_counts()
)


# ============================================================
# KEV distribution
# ============================================================

print(
    "\nKEV distribution:"
)

print(
    sample[
        "kev_status"
    ].value_counts()
)