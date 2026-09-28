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
    "phase1_context_sensitivity.csv"
)


# ============================================================
# Controlled Asset Scenarios
# ============================================================

ASSET_SCENARIOS = {
    "Development System": 0.30,
    "Internal Application": 0.60,
    "Business Application": 0.80,
    "Public-Facing Production": 1.00
}


# ============================================================
# Risk Calculation
# ============================================================

def calculate_risk(row, asset_criticality):

    cvss = min(
        max(float(row["cvss_score"]) / 10.0, 0.0),
        1.0
    )

    kev = (
        1.0
        if int(row["kev_status"]) == 1
        else 0.0
    )

    epss = row["epss_score"]

    # --------------------------------------------------------
    # EPSS available
    # --------------------------------------------------------

    if pd.notna(epss):

        score = (
            0.30 * cvss
            + 0.30 * float(epss)
            + 0.20 * kev
            + 0.20 * asset_criticality
        )

    # --------------------------------------------------------
    # EPSS unavailable
    # --------------------------------------------------------

    else:

        score = (
            0.43 * cvss
            + 0.29 * kev
            + 0.28 * asset_criticality
        )

    return round(score * 100, 2)


# ============================================================
# Main Experiment
# ============================================================

def run_experiment():

    print("\n============================================================")
    print(" VulnPilot-X Phase 1: Context Sensitivity Experiment")
    print("============================================================")

    print("\nLoading Phase 1 master dataset...")

    df = pd.read_csv(INPUT_PATH)

    print(
        f"Dataset records: {len(df)}"
    )

    # --------------------------------------------------------
    # Select representative vulnerabilities
    # --------------------------------------------------------
    #
    # We deliberately select:
    # 1. A high-risk KEV vulnerability
    # 2. A non-KEV vulnerability
    # 3. A lower-CVSS vulnerability
    #
    # This allows us to demonstrate how asset context changes
    # the resulting risk score.
    # --------------------------------------------------------

    selected_rows = []

    # High-risk KEV
    kev_candidates = df[
        df["kev_status"] == 1
    ].sort_values(
        by=[
            "epss_score",
            "cvss_score"
        ],
        ascending=False
    )

    if len(kev_candidates) > 0:

        selected_rows.append(
            kev_candidates.iloc[0]
        )

    # High EPSS non-KEV
    non_kev_candidates = df[
        df["kev_status"] == 0
    ].sort_values(
        by=[
            "epss_score",
            "cvss_score"
        ],
        ascending=False
    )

    if len(non_kev_candidates) > 0:

        selected_rows.append(
            non_kev_candidates.iloc[0]
        )

    # Lower CVSS vulnerability
    lower_cvss_candidates = df[
        df["cvss_score"] <= 5.0
    ].sort_values(
        by=[
            "epss_score",
            "cvss_score"
        ],
        ascending=False
    )

    if len(lower_cvss_candidates) > 0:

        selected_rows.append(
            lower_cvss_candidates.iloc[0]
        )

    # --------------------------------------------------------
    # Remove duplicate CVEs
    # --------------------------------------------------------

    selected = pd.DataFrame(
        selected_rows
    ).drop_duplicates(
        subset=["cve_id"]
    )

    print(
        f"Selected vulnerabilities: {len(selected)}"
    )

    # --------------------------------------------------------
    # Generate scenarios
    # --------------------------------------------------------

    results = []

    for _, row in selected.iterrows():

        for asset_type, asset_criticality in ASSET_SCENARIOS.items():

            risk_score = calculate_risk(
                row,
                asset_criticality
            )

            results.append(
                {
                    "cve_id": row["cve_id"],
                    "cvss_score": row["cvss_score"],
                    "epss_score": row["epss_score"],
                    "kev_status": row["kev_status"],
                    "asset_type": asset_type,
                    "asset_criticality": asset_criticality,
                    "contextual_risk_score": risk_score
                }
            )

    result_df = pd.DataFrame(results)

    # --------------------------------------------------------
    # Calculate change relative to lowest asset context
    # --------------------------------------------------------

    result_df["risk_change_from_development"] = (
        result_df.groupby("cve_id")[
            "contextual_risk_score"
        ]
        .transform("first")
    )

    result_df["risk_change_from_development"] = (
        result_df["contextual_risk_score"]
        - result_df["risk_change_from_development"]
    ).round(2)

    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    result_df.to_csv(
        OUTPUT_PATH,
        index=False,
        encoding="utf-8"
    )

    # --------------------------------------------------------
    # Display
    # --------------------------------------------------------

    print("\n------------------------------------------------------------")
    print("Context Sensitivity Results")
    print("------------------------------------------------------------")

    print(
        result_df.to_string(
            index=False
        )
    )

    # --------------------------------------------------------
    # Validation
    # --------------------------------------------------------

    print("\n------------------------------------------------------------")
    print("Validation")
    print("------------------------------------------------------------")

    all_monotonic = True

    for cve_id, group in result_df.groupby("cve_id"):

        scores = group[
            "contextual_risk_score"
        ].tolist()

        is_monotonic = (
            scores == sorted(scores)
        )

        print(
            f"{cve_id}: "
            f"{'PASS' if is_monotonic else 'FAIL'}"
        )

        if not is_monotonic:

            all_monotonic = False

    print()

    if all_monotonic:

        print(
            "PASS: Contextual risk increases "
            "with asset criticality for all tested CVEs."
        )

    else:

        print(
            "WARNING: At least one CVE did not show "
            "monotonic context sensitivity."
        )

    print("\n============================================================")

    print(
        f"Output saved to:\n{OUTPUT_PATH}"
    )

    print("============================================================")

    return result_df


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":

    run_experiment()