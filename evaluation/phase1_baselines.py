import os
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
    "phase1_master_dataset.csv"
)

OUTPUT_PATH = os.path.join(
    BASE_DIR,
    "data",
    "processed",
    "phase1_baseline_rankings.csv"
)


# ============================================================
# Load data
# ============================================================

print("=" * 70)
print("VulnPilot-X - Phase 1 Baseline Strategies")
print("=" * 70)

df = pd.read_csv(
    INPUT_PATH
)

print(
    f"\nRecords loaded: {len(df)}"
)


# ============================================================
# Validate required columns
# ============================================================

required_columns = [
    "cve_id",
    "cvss_score",
    "epss_score",
    "kev_status",
    "epss_available"
]

missing = [
    col
    for col in required_columns
    if col not in df.columns
]

if missing:

    raise ValueError(
        f"Missing columns: {missing}"
    )


# ============================================================
# Normalize CVSS
# ============================================================

df["cvss_normalized"] = (
    df["cvss_score"] / 10.0
)


# ============================================================
# Prepare EPSS
# ============================================================

# IMPORTANT:
# Missing EPSS is NOT treated as zero exploitability.
#
# For the baseline rankings below, missing EPSS is left as NaN.
# Rankings that depend on EPSS will therefore be evaluated
# only where EPSS is available.

df["epss_score"] = pd.to_numeric(
    df["epss_score"],
    errors="coerce"
)

df["kev_status"] = (
    df["kev_status"]
    .fillna(0)
    .astype(int)
)


# ============================================================
# Strategy 1: CVSS-only
# ============================================================

df["score_cvss_only"] = (
    df["cvss_normalized"]
)


# ============================================================
# Strategy 2: EPSS-only
# ============================================================

df["score_epss_only"] = (
    df["epss_score"]
)


# ============================================================
# Strategy 3: CVSS + EPSS
# ============================================================

# Equal weighting.
#
# This is a transparent baseline, NOT the proposed
# VulnPilot-X weighting.

df["score_cvss_epss"] = (
    0.50 * df["cvss_normalized"]
    +
    0.50 * df["epss_score"]
)


# ============================================================
# Strategy 4: CVSS + EPSS + KEV
# ============================================================

# Equal weighting across the three normalized signals.

df["score_cvss_epss_kev"] = (
    (1 / 3) * df["cvss_normalized"]
    +
    (1 / 3) * df["epss_score"]
    +
    (1 / 3) * df["kev_status"]
)


# ============================================================
# Ranking helper
# ============================================================

def add_rank(
    data,
    score_column,
    rank_column
):

    # Stable deterministic ordering:
    #
    # 1. score descending
    # 2. CVSS descending
    # 3. EPSS descending
    # 4. CVE ID ascending

    data = data.sort_values(
        by=[
            score_column,
            "cvss_score",
            "epss_score",
            "cve_id"
        ],
        ascending=[
            False,
            False,
            False,
            True
        ],
        na_position="last"
    ).copy()

    data[rank_column] = (
        range(1, len(data) + 1)
    )

    return data


# ============================================================
# Create rankings
# ============================================================

df = add_rank(
    df,
    "score_cvss_only",
    "rank_cvss_only"
)

df = add_rank(
    df,
    "score_epss_only",
    "rank_epss_only"
)

df = add_rank(
    df,
    "score_cvss_epss",
    "rank_cvss_epss"
)

df = add_rank(
    df,
    "score_cvss_epss_kev",
    "rank_cvss_epss_kev"
)


# ============================================================
# Restore CVE order
# ============================================================

df = df.sort_values(
    "cve_id"
).reset_index(
    drop=True
)


# ============================================================
# Save
# ============================================================

df.to_csv(
    OUTPUT_PATH,
    index=False,
    encoding="utf-8"
)


# ============================================================
# Summary
# ============================================================

print("\n" + "=" * 70)
print("BASELINE RANKINGS CREATED")
print("=" * 70)

print(
    f"\nTotal records: {len(df)}"
)

print(
    f"EPSS available: "
    f"{df['epss_score'].notna().sum()}"
)

print(
    f"EPSS missing: "
    f"{df['epss_score'].isna().sum()}"
)

print(
    f"\nSaved to:\n{OUTPUT_PATH}"
)


# ============================================================
# Top 10 - each strategy
# ============================================================

strategies = [
    (
        "CVSS-only",
        "score_cvss_only",
        "rank_cvss_only"
    ),
    (
        "EPSS-only",
        "score_epss_only",
        "rank_epss_only"
    ),
    (
        "CVSS + EPSS",
        "score_cvss_epss",
        "rank_cvss_epss"
    ),
    (
        "CVSS + EPSS + KEV",
        "score_cvss_epss_kev",
        "rank_cvss_epss_kev"
    )
]


for name, score, rank in strategies:

    print("\n" + "-" * 70)

    print(
        f"TOP 10 — {name}"
    )

    print("-" * 70)

    top = df.sort_values(
        by=rank
    ).head(10)

    print(
        top[
            [
                "cve_id",
                "cvss_score",
                "epss_score",
                "kev_status",
                score,
                rank
            ]
        ].to_string(
            index=False
        )
    )


print("\n" + "=" * 70)
print("COMPLETED")
print("=" * 70)