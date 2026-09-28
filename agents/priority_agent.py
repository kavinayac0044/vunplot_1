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
    "phase1_context_analysis.csv"
)

OUTPUT_PATH = os.path.join(
    BASE_DIR,
    "data",
    "processed",
    "phase1_priority_results.csv"
)


# ============================================================
# Priority Agent
# ============================================================

def prioritize_vulnerabilities():

    print("\n============================================================")
    print(" VulnPilot-X Phase 1: Priority Agent")
    print("============================================================")

    print("\nLoading context analysis...")

    df = pd.read_csv(INPUT_PATH)

    print(f"Input records: {len(df)}")

    # --------------------------------------------------------
    # Validate required columns
    # --------------------------------------------------------

    required_columns = [
        "cve_id",
        "cvss_score",
        "epss_score",
        "kev_status",
        "asset_type",
        "asset_criticality",
        "contextual_risk_score",
        "priority"
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
    # Preserve original CVSS rank
    # --------------------------------------------------------

    cvss_sorted = df.sort_values(
        by=[
            "cvss_score",
            "cve_id"
        ],
        ascending=[
            False,
            True
        ]
    ).reset_index(drop=True)

    cvss_sorted["cvss_rank"] = (
        cvss_sorted.index + 1
    )

    cvss_rank_map = dict(
        zip(
            cvss_sorted["cve_id"],
            cvss_sorted["cvss_rank"]
        )
    )

    df["cvss_rank"] = df["cve_id"].map(
        cvss_rank_map
    )

    # --------------------------------------------------------
    # Sort using VulnPilot-X contextual score
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
    # Final VulnPilot-X rank
    # --------------------------------------------------------

    df["final_priority_rank"] = (
        df.index + 1
    )

    # --------------------------------------------------------
    # Rank movement compared with CVSS
    # --------------------------------------------------------

    df["rank_change_vs_cvss"] = (
        df["cvss_rank"]
        - df["final_priority_rank"]
    )

    def classify_rank_change(value):

        if value > 0:
            return "Moved Up"

        elif value < 0:
            return "Moved Down"

        else:
            return "Unchanged"

    df["rank_movement"] = (
        df["rank_change_vs_cvss"]
        .apply(classify_rank_change)
    )

    # --------------------------------------------------------
    # Priority action
    # --------------------------------------------------------

    def priority_action(priority):

        if priority == "Critical":

            return (
                "Immediate vulnerability review "
                "and remediation planning"
            )

        elif priority == "High":

            return (
                "Near-term security review "
                "and remediation"
            )

        elif priority == "Medium":

            return (
                "Schedule remediation based "
                "on organizational risk policy"
            )

        else:

            return (
                "Monitor through routine "
                "vulnerability management"
            )

    df["priority_action"] = (
        df["priority"]
        .apply(priority_action)
    )

    # --------------------------------------------------------
    # Risk evidence summary
    # --------------------------------------------------------

    def evidence_summary(row):

        evidence = []

        if row["cvss_score"] >= 9:

            evidence.append("Very High CVSS")

        elif row["cvss_score"] >= 7:

            evidence.append("High CVSS")

        if pd.notna(row["epss_score"]):

            if row["epss_score"] >= 0.90:

                evidence.append("Very High EPSS")

            elif row["epss_score"] >= 0.50:

                evidence.append("High EPSS")

        if int(row["kev_status"]) == 1:

            evidence.append("CISA KEV")

        if row["asset_criticality"] >= 0.80:

            evidence.append("High Asset Criticality")

        elif row["asset_criticality"] >= 0.60:

            evidence.append("Moderate Asset Criticality")

        if not evidence:

            evidence.append("Limited high-risk evidence")

        return "; ".join(evidence)

    df["risk_evidence"] = df.apply(
        evidence_summary,
        axis=1
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
    print("Priority Agent Summary")
    print("------------------------------------------------------------")

    print(
        f"Total vulnerabilities : {len(df)}"
    )

    print(
        f"Moved up             : "
        f"{(df['rank_change_vs_cvss'] > 0).sum()}"
    )

    print(
        f"Moved down           : "
        f"{(df['rank_change_vs_cvss'] < 0).sum()}"
    )

    print(
        f"Unchanged            : "
        f"{(df['rank_change_vs_cvss'] == 0).sum()}"
    )

    print("\nPriority distribution:")

    print(
        df["priority"]
        .value_counts()
        .to_string()
    )

    # --------------------------------------------------------
    # Top vulnerabilities
    # --------------------------------------------------------

    print("\nTop 20 VulnPilot-X priorities:")

    print(
        df[
            [
                "final_priority_rank",
                "cve_id",
                "cvss_score",
                "epss_score",
                "kev_status",
                "asset_type",
                "contextual_risk_score",
                "priority",
                "cvss_rank",
                "rank_change_vs_cvss",
                "rank_movement",
                "risk_evidence"
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

    prioritize_vulnerabilities()