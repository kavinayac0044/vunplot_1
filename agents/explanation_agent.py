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
    "phase1_priority_results.csv"
)

OUTPUT_PATH = os.path.join(
    BASE_DIR,
    "data",
    "processed",
    "phase1_explanation_results.csv"
)


# ============================================================
# Score Contributions
# ============================================================

def calculate_contributions(row):

    cvss = min(max(float(row["cvss_score"]) / 10.0, 0.0), 1.0)

    epss = row["epss_score"]

    kev = (
        1.0
        if int(row["kev_status"]) == 1
        else 0.0
    )

    asset = float(row["asset_criticality"])

    # --------------------------------------------------------
    # EPSS available
    # --------------------------------------------------------

    if pd.notna(epss):

        cvss_contribution = cvss * 30
        epss_contribution = float(epss) * 30
        kev_contribution = kev * 20
        asset_contribution = asset * 20

        evidence_status = (
            "CVSS + EPSS + KEV + Asset"
        )

    # --------------------------------------------------------
    # EPSS unavailable
    # --------------------------------------------------------

    else:

        cvss_contribution = cvss * 43
        epss_contribution = 0.0
        kev_contribution = kev * 29
        asset_contribution = asset * 28

        evidence_status = (
            "CVSS + KEV + Asset "
            "(EPSS unavailable)"
        )

   return pd.Series(
    {
        # Keep full precision internally.
        # Rounding will only be applied when displaying results.
        "cvss_contribution": cvss_contribution,
        "epss_contribution": epss_contribution,
        "kev_contribution": kev_contribution,
        "asset_contribution": asset_contribution,
        "evidence_status": evidence_status
    }
)


# ============================================================
# Evidence Explanation
# ============================================================

def generate_evidence_explanation(row):

    reasons = []

    # --------------------------------------------------------
    # CVSS
    # --------------------------------------------------------

    cvss = float(row["cvss_score"])

    if cvss >= 9:

        reasons.append(
            f"Very high technical severity "
            f"(CVSS {cvss:.1f})"
        )

    elif cvss >= 7:

        reasons.append(
            f"High technical severity "
            f"(CVSS {cvss:.1f})"
        )

    elif cvss >= 4:

        reasons.append(
            f"Moderate technical severity "
            f"(CVSS {cvss:.1f})"
        )

    else:

        reasons.append(
            f"Low technical severity "
            f"(CVSS {cvss:.1f})"
        )

    # --------------------------------------------------------
    # EPSS
    # --------------------------------------------------------

    if pd.notna(row["epss_score"]):

        epss = float(row["epss_score"])

        if epss >= 0.90:

            reasons.append(
                f"Very high exploitation likelihood "
                f"(EPSS {epss:.5f})"
            )

        elif epss >= 0.50:

            reasons.append(
                f"High exploitation likelihood "
                f"(EPSS {epss:.5f})"
            )

        elif epss >= 0.10:

            reasons.append(
                f"Moderate exploitation likelihood "
                f"(EPSS {epss:.5f})"
            )

        else:

            reasons.append(
                f"Low estimated exploitation likelihood "
                f"(EPSS {epss:.5f})"
            )

    else:

        reasons.append(
            "EPSS score unavailable for this CVE"
        )

    # --------------------------------------------------------
    # KEV
    # --------------------------------------------------------

    if int(row["kev_status"]) == 1:

        reasons.append(
            "Listed in the CISA Known Exploited "
            "Vulnerabilities catalog"
        )

    else:

        reasons.append(
            "No CISA KEV listing in the evaluated data"
        )

    # --------------------------------------------------------
    # Asset Context
    # --------------------------------------------------------

    asset_type = str(
        row["asset_type"]
    )

    asset_criticality = float(
        row["asset_criticality"]
    )

    reasons.append(
        f"Evaluated against controlled asset context: "
        f"{asset_type} "
        f"(criticality {asset_criticality:.2f})"
    )

    return "; ".join(reasons)


# ============================================================
# Rank Movement Explanation
# ============================================================

def generate_rank_explanation(row):

    movement = row["rank_movement"]

    change = int(
        row["rank_change_vs_cvss"]
    )

    cvss_rank = int(
        row["cvss_rank"]
    )

    final_rank = int(
        row["final_priority_rank"]
    )

    if movement == "Moved Up":

        return (
            f"Moved up by {change} positions "
            f"from CVSS rank {cvss_rank} "
            f"to VulnPilot-X rank {final_rank}, "
            f"because additional exploitation and "
            f"contextual evidence increased its priority."
        )

    elif movement == "Moved Down":

        return (
            f"Moved down by {abs(change)} positions "
            f"from CVSS rank {cvss_rank} "
            f"to VulnPilot-X rank {final_rank}, "
            f"because its contextual score was lower "
            f"relative to other vulnerabilities."
        )

    else:

        return (
            f"Ranking remained unchanged at position "
            f"{final_rank}."
        )


# ============================================================
# Priority Recommendation
# ============================================================

def generate_recommendation(priority):

    if priority == "Critical":

        return (
            "Immediate vulnerability review and "
            "remediation planning."
        )

    elif priority == "High":

        return (
            "Near-term security review and "
            "remediation."
        )

    elif priority == "Medium":

        return (
            "Schedule remediation according to "
            "organizational risk policy."
        )

    else:

        return (
            "Monitor through routine vulnerability "
            "management and maintenance."
        )


# ============================================================
# Complete Explanation
# ============================================================

def generate_full_explanation(row):

    evidence = generate_evidence_explanation(row)

    movement = generate_rank_explanation(row)

    priority = row["priority"]

    score = float(
        row["contextual_risk_score"]
    )

    return (
        f"VulnPilot-X assigned a contextual risk score "
        f"of {score:.2f} and classified the vulnerability "
        f"as {priority}. "
        f"{evidence}. "
        f"{movement}"
    )


# ============================================================
# Main
# ============================================================

def generate_explanations():

    print("\n============================================================")
    print(" VulnPilot-X Phase 1: Explainability Agent")
    print("============================================================")

    print("\nLoading priority results...")

    df = pd.read_csv(INPUT_PATH)

    print(
        f"Input records: {len(df)}"
    )

    # --------------------------------------------------------
    # Calculate score contributions
    # --------------------------------------------------------

    contributions = df.apply(
        calculate_contributions,
        axis=1
    )

    for column in contributions.columns:

        df[column] = contributions[column]

    # --------------------------------------------------------
    # Evidence explanation
    # --------------------------------------------------------

    df["evidence_explanation"] = df.apply(
        generate_evidence_explanation,
        axis=1
    )

    # --------------------------------------------------------
    # Rank explanation
    # --------------------------------------------------------

    df["rank_explanation"] = df.apply(
        generate_rank_explanation,
        axis=1
    )

    # --------------------------------------------------------
    # Final explanation
    # --------------------------------------------------------

    df["explanation"] = df.apply(
        generate_full_explanation,
        axis=1
    )

    # --------------------------------------------------------
    # Recommendation
    # --------------------------------------------------------

    df["recommendation"] = (
        df["priority"]
        .apply(generate_recommendation)
    )

    # --------------------------------------------------------
    # Score verification
    # --------------------------------------------------------

    # --------------------------------------------------------
# Exact score verification
# --------------------------------------------------------

df["contribution_total"] = (
    df["cvss_contribution"]
    + df["epss_contribution"]
    + df["kev_contribution"]
    + df["asset_contribution"]
)

df["score_difference"] = (
    df["contextual_risk_score"]
    - df["contribution_total"]
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
    print("Explainability Summary")
    print("------------------------------------------------------------")

    print(
        f"Total vulnerabilities : {len(df)}"
    )

    print(
        f"Average contextual score : "
        f"{df['contextual_risk_score'].mean():.2f}"
    )

    print(
        f"Score verification maximum difference : "
        f"{df['score_difference'].abs().max():.2f}"
    )

    # --------------------------------------------------------
    # Top 10 explanations
    # --------------------------------------------------------

    print("\nTop 10 Explainable Priorities:")

    for _, row in df.head(10).iterrows():

        print("\n--------------------------------------------------------")

        print(
            f"Rank       : {row['final_priority_rank']}"
        )

        print(
            f"CVE        : {row['cve_id']}"
        )

        print(
            f"CVSS       : {row['cvss_score']}"
        )

        print(
            f"EPSS       : {row['epss_score']}"
        )

        print(
            f"KEV        : {row['kev_status']}"
        )

        print(
            f"Asset      : {row['asset_type']}"
        )

        print(
            f"Risk Score : "
            f"{row['contextual_risk_score']}"
        )

        print(
            f"Priority   : {row['priority']}"
        )

        print(
            "\nScore Contributions:"
        )

        print(
            f"  CVSS  : "
            f"{row['cvss_contribution']}"
        )

        print(
            f"  EPSS  : "
            f"{row['epss_contribution']}"
        )

        print(
            f"  KEV   : "
            f"{row['kev_contribution']}"
        )

        print(
            f"  Asset : "
            f"{row['asset_contribution']}"
        )

        print(
            "\nWhy?"
        )

        print(
            row["explanation"]
        )

        print(
            "\nRecommendation:"
        )

        print(
            row["recommendation"]
        )

    print("\n============================================================")

    print(
        f"Output saved to:\n{OUTPUT_PATH}"
    )

    print("============================================================")

    return df


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":

    generate_explanations()