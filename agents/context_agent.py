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
    "phase1_context_analysis.csv"
)


# ============================================================
# Configuration for Controlled Asset Context
# ============================================================
#
# IMPORTANT:
# These asset values are controlled experimental assumptions.
# They are NOT real enterprise asset inventory data.
#
# They allow Phase 1 to demonstrate how asset criticality
# can influence vulnerability prioritization.
# ============================================================

ASSET_CRITICALITY = {
    "Public-Facing Production": 1.00,
    "Business Application": 0.80,
    "Internal Application": 0.60,
    "Development System": 0.30
}


# ============================================================
# CVSS Normalization
# ============================================================

def normalize_cvss(score):
    if pd.isna(score):
        return 0.0

    return min(max(float(score) / 10.0, 0.0), 1.0)


# ============================================================
# EPSS Handling
# ============================================================

def normalize_epss(score):
    """
    EPSS is already represented as a probability between 0 and 1.

    Missing EPSS is NOT treated as zero.
    Instead, the EPSS contribution is excluded from the
    available-evidence calculation.
    """

    if pd.isna(score):
        return None

    return min(max(float(score), 0.0), 1.0)


# ============================================================
# KEV Handling
# ============================================================

def normalize_kev(value):

    if pd.isna(value):
        return 0.0

    return 1.0 if int(value) == 1 else 0.0


# ============================================================
# Asset Context
# ============================================================

def assign_asset_context(index):

    """
    Controlled experimental asset assignment.

    A deterministic cycle is used so that every vulnerability
    receives an experimental asset context without introducing
    random results.
    """

    asset_types = list(ASSET_CRITICALITY.keys())

    asset_type = asset_types[index % len(asset_types)]

    return asset_type, ASSET_CRITICALITY[asset_type]


# ============================================================
# Context-Aware Risk Score
# ============================================================

def calculate_context_score(row):

    cvss = normalize_cvss(row["cvss_score"])
    epss = normalize_epss(row["epss_score"])
    kev = normalize_kev(row["kev_status"])
    asset = float(row["asset_criticality"])

    # --------------------------------------------------------
    # Evidence-aware weighting
    # --------------------------------------------------------
    #
    # CVSS represents technical severity.
    # EPSS represents exploitation likelihood.
    # KEV represents confirmed exploitation evidence.
    # Asset criticality represents business/environment context.
    #
    # When EPSS is unavailable, its weight is redistributed
    # proportionally rather than treating missing EPSS as 0.
    # --------------------------------------------------------

    if epss is not None:

        score = (
            0.30 * cvss
            + 0.30 * epss
            + 0.20 * kev
            + 0.20 * asset
        )

        evidence_status = "CVSS + EPSS + KEV + Asset"

    else:

        score = (
            0.43 * cvss
            + 0.29 * kev
            + 0.28 * asset
        )

        evidence_status = "CVSS + KEV + Asset (EPSS unavailable)"

    return round(score * 100, 2), evidence_status


# ============================================================
# Priority Classification
# ============================================================

def classify_priority(score):

    if score >= 80:
        return "Critical"

    elif score >= 60:
        return "High"

    elif score >= 40:
        return "Medium"

    else:
        return "Low"


# ============================================================
# Main Analysis
# ============================================================

def analyze_vulnerabilities():

    print("\n============================================================")
    print(" VulnPilot-X Phase 1: Context-Aware Analysis")
    print("============================================================")

    print("\nLoading Phase 1 master dataset...")

    df = pd.read_csv(INPUT_PATH)

    print(f"Input records: {len(df)}")

    required_columns = [
        "cve_id",
        "cvss_score",
        "kev_status",
        "epss_score"
    ]

    missing_columns = [
        column
        for column in required_columns
        if column not in df.columns
    ]

    if missing_columns:

        raise ValueError(
            f"Missing required columns: {missing_columns}"
        )

    # --------------------------------------------------------
    # EPSS availability
    # --------------------------------------------------------

    df["epss_available"] = (
        df["epss_score"]
        .notna()
        .astype(int)
    )

    # --------------------------------------------------------
    # Controlled asset context
    # --------------------------------------------------------

    asset_data = [
        assign_asset_context(index)
        for index in range(len(df))
    ]

    df["asset_type"] = [
        item[0]
        for item in asset_data
    ]

    df["asset_criticality"] = [
        item[1]
        for item in asset_data
    ]

    # --------------------------------------------------------
    # Calculate context-aware score
    # --------------------------------------------------------

    results = df.apply(
        calculate_context_score,
        axis=1,
        result_type="expand"
    )

    results.columns = [
        "contextual_risk_score",
        "evidence_status"
    ]

    df["contextual_risk_score"] = results[
        "contextual_risk_score"
    ]

    df["evidence_status"] = results[
        "evidence_status"
    ]

    # --------------------------------------------------------
    # Priority
    # --------------------------------------------------------

    df["priority"] = (
        df["contextual_risk_score"]
        .apply(classify_priority)
    )

    # --------------------------------------------------------
    # Sort vulnerabilities
    # --------------------------------------------------------

    df = df.sort_values(
        by=[
            "contextual_risk_score",
            "cvss_score",
            "epss_score",
            "kev_status",
            "cve_id"
        ],
        ascending=[
            False,
            False,
            False,
            False,
            True
        ],
        na_position="last"
    ).reset_index(drop=True)

    # --------------------------------------------------------
    # Contextual rank
    # --------------------------------------------------------

    df["contextual_rank"] = (
        df.index + 1
    )

    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    df.to_csv(
        OUTPUT_PATH,
        index=False,
        encoding="utf-8"
    )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    print("\n------------------------------------------------------------")
    print("Phase 1 Context Analysis Summary")
    print("------------------------------------------------------------")

    print(f"Total vulnerabilities : {len(df)}")

    print(
        f"EPSS available       : "
        f"{df['epss_available'].sum()}"
    )

    print(
        f"EPSS unavailable     : "
        f"{len(df) - df['epss_available'].sum()}"
    )

    print(
        f"KEV confirmed        : "
        f"{df['kev_status'].sum()}"
    )

    print("\nPriority distribution:")

    print(
        df["priority"]
        .value_counts()
        .to_string()
    )

    print("\nTop 20 vulnerabilities:")

    print(
        df[
            [
                "contextual_rank",
                "cve_id",
                "cvss_score",
                "epss_score",
                "kev_status",
                "asset_type",
                "asset_criticality",
                "contextual_risk_score",
                "priority"
            ]
        ]
        .head(20)
        .to_string(index=False)
    )

    print("\n------------------------------------------------------------")

    print(
        f"Output saved to:\n{OUTPUT_PATH}"
    )

    print("------------------------------------------------------------")

    return df


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":

    analyze_vulnerabilities()