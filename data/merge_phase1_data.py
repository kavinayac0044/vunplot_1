import os
import pandas as pd


# ============================================================
# Configuration
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

SAMPLE_PATH = os.path.join(
    BASE_DIR,
    "data",
    "processed",
    "phase1_experimental_sample.csv"
)

EPSS_PATH = os.path.join(
    BASE_DIR,
    "data",
    "processed",
    "phase1_epss_scores.csv"
)

OUTPUT_PATH = os.path.join(
    BASE_DIR,
    "data",
    "processed",
    "phase1_master_dataset.csv"
)


# ============================================================
# Load datasets
# ============================================================

print("=" * 70)
print("VulnPilot-X - Phase 1 Master Dataset")
print("=" * 70)

sample = pd.read_csv(
    SAMPLE_PATH
)

epss = pd.read_csv(
    EPSS_PATH
)

print(
    f"\nExperimental sample : {len(sample)}"
)

print(
    f"EPSS records        : {len(epss)}"
)


# ============================================================
# Validate CVE uniqueness
# ============================================================

if sample["cve_id"].duplicated().any():

    raise ValueError(
        "Duplicate CVE IDs found in experimental sample."
    )

if epss["cve_id"].duplicated().any():

    raise ValueError(
        "Duplicate CVE IDs found in EPSS dataset."
    )


# ============================================================
# Merge
# ============================================================

master = sample.merge(
    epss[
        [
            "cve_id",
            "epss_score",
            "epss_percentile"
        ]
    ],
    on="cve_id",
    how="left",
    validate="one_to_one"
)


# ============================================================
# EPSS availability
# ============================================================

master["epss_available"] = (
    master["epss_score"]
    .notna()
    .astype(int)
)


# ============================================================
# Numeric conversion
# ============================================================

master["cvss_score"] = pd.to_numeric(
    master["cvss_score"],
    errors="coerce"
)

master["epss_score"] = pd.to_numeric(
    master["epss_score"],
    errors="coerce"
)

master["epss_percentile"] = pd.to_numeric(
    master["epss_percentile"],
    errors="coerce"
)

master["kev_status"] = (
    master["kev_status"]
    .fillna(0)
    .astype(int)
)


# ============================================================
# Sort
# ============================================================

master = master.sort_values(
    by=[
        "kev_status",
        "epss_score",
        "cvss_score"
    ],
    ascending=[
        False,
        False,
        False
    ]
).reset_index(
    drop=True
)


# ============================================================
# Save
# ============================================================

master.to_csv(
    OUTPUT_PATH,
    index=False,
    encoding="utf-8"
)


# ============================================================
# Validation
# ============================================================

print("\n" + "=" * 70)
print("MASTER DATASET CREATED")
print("=" * 70)

print(
    f"\nTotal records       : {len(master)}"
)

print(
    f"KEV records         : "
    f"{master['kev_status'].sum()}"
)

print(
    f"Non-KEV records     : "
    f"{(master['kev_status'] == 0).sum()}"
)

print(
    f"EPSS available      : "
    f"{master['epss_available'].sum()}"
)

print(
    f"EPSS unavailable    : "
    f"{(master['epss_available'] == 0).sum()}"
)

print(
    f"\nSaved to:\n{OUTPUT_PATH}"
)


# ============================================================
# Columns
# ============================================================

print(
    "\nColumns:"
)

for column in master.columns:

    print(
        f"  - {column}"
    )


# ============================================================
# Sample
# ============================================================

print(
    "\nSample records:"
)

print(
    master[
        [
            "cve_id",
            "cvss_score",
            "cvss_version",
            "epss_score",
            "epss_percentile",
            "epss_available",
            "kev_status"
        ]
    ]
    .head(10)
    .to_string(index=False)
)