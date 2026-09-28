import os
import time
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
    "processed",
    "phase1_experimental_sample.csv"
)

OUTPUT_PATH = os.path.join(
    BASE_DIR,
    "data",
    "processed",
    "phase1_epss_scores.csv"
)

EPSS_API = "https://api.first.org/data/v1/epss"

BATCH_SIZE = 100

REQUEST_DELAY = 0.5


# ============================================================
# Load Phase-1 sample
# ============================================================

print("=" * 70)
print("VulnPilot-X - Phase 1 EPSS Collection")
print("=" * 70)

if not os.path.exists(INPUT_PATH):

    raise FileNotFoundError(
        f"Input file not found:\n{INPUT_PATH}"
    )


df = pd.read_csv(
    INPUT_PATH
)

cve_ids = (
    df["cve_id"]
    .dropna()
    .astype(str)
    .unique()
    .tolist()
)

print(
    f"\nPhase-1 CVEs: {len(cve_ids)}"
)


# ============================================================
# Download EPSS in batches
# ============================================================

all_records = []

total_batches = (
    (len(cve_ids) + BATCH_SIZE - 1)
    // BATCH_SIZE
)


for batch_number, start in enumerate(
    range(0, len(cve_ids), BATCH_SIZE),
    start=1
):

    batch = cve_ids[
        start:start + BATCH_SIZE
    ]

    cve_parameter = ",".join(
        batch
    )

    print(
        f"\nBatch {batch_number}/{total_batches}"
    )

    print(
        f"CVEs: {len(batch)}"
    )

    try:

        response = requests.get(
            EPSS_API,
            params={
                "cve": cve_parameter
            },
            timeout=60
        )

        response.raise_for_status()

        data = response.json()

        records = data.get(
            "data",
            []
        )

        all_records.extend(
            records
        )

        print(
            f"EPSS records received: "
            f"{len(records)}"
        )

    except requests.RequestException as e:

        print(
            f"ERROR in batch {batch_number}: {e}"
        )

    time.sleep(
        REQUEST_DELAY
    )


# ============================================================
# Convert to DataFrame
# ============================================================

epss_df = pd.DataFrame(
    all_records
)


if epss_df.empty:

    raise RuntimeError(
        "No EPSS records were received."
    )


# ============================================================
# Keep required columns
# ============================================================

required_columns = [
    "cve",
    "epss",
    "percentile"
]

missing_columns = [
    col
    for col in required_columns
    if col not in epss_df.columns
]

if missing_columns:

    raise RuntimeError(
        f"Missing EPSS columns: "
        f"{missing_columns}"
    )


epss_df = epss_df[
    required_columns
].copy()


epss_df = epss_df.rename(
    columns={
        "cve": "cve_id",
        "epss": "epss_score",
        "percentile": "epss_percentile"
    }
)


# ============================================================
# Remove duplicate CVEs
# ============================================================

epss_df = epss_df.drop_duplicates(
    subset=["cve_id"]
)


# ============================================================
# Validate coverage
# ============================================================

requested = set(
    cve_ids
)

received = set(
    epss_df["cve_id"]
)


missing = requested - received


# ============================================================
# Convert numeric fields
# ============================================================

epss_df["epss_score"] = pd.to_numeric(
    epss_df["epss_score"],
    errors="coerce"
)

epss_df["epss_percentile"] = pd.to_numeric(
    epss_df["epss_percentile"],
    errors="coerce"
)


# ============================================================
# Save
# ============================================================

os.makedirs(
    os.path.dirname(OUTPUT_PATH),
    exist_ok=True
)

epss_df.to_csv(
    OUTPUT_PATH,
    index=False,
    encoding="utf-8"
)


# ============================================================
# Summary
# ============================================================

available = (
    epss_df["epss_score"]
    .notna()
    .sum()
)

missing_score = (
    len(cve_ids)
    - available
)


print("\n" + "=" * 70)
print("PHASE 1 EPSS COLLECTION COMPLETED")
print("=" * 70)

print(
    f"\nRequested CVEs : {len(cve_ids)}"
)

print(
    f"EPSS records   : {len(epss_df)}"
)

print(
    f"EPSS available : {available}"
)

print(
    f"EPSS missing   : {missing_score}"
)

print(
    f"Missing CVEs   : {len(missing)}"
)

print(
    f"\nSaved to:\n{OUTPUT_PATH}"
)


# ============================================================
# Sample output
# ============================================================

print(
    "\nSample EPSS records:"
)

print(
    epss_df
    .head(10)
    .to_string(index=False)
)