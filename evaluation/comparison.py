import os
import pandas as pd
import numpy as np
from scipy.stats import spearmanr


# ============================================================
# Configuration
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

CVSS_PATH = os.path.join(
    BASE_DIR,
    "data",
    "processed",
    "real_cvss_baseline.csv"
)

PRIORITY_PATH = os.path.join(
    BASE_DIR,
    "data",
    "processed",
    "real_priority_results.csv"
)

OUTPUT_PATH = os.path.join(
    BASE_DIR,
    "data",
    "processed",
    "real_ranking_comparison.csv"
)

METRICS_PATH = os.path.join(
    BASE_DIR,
    "data",
    "processed",
    "quantitative_evaluation.csv"
)


# ============================================================
# Load and Compare Rankings
# ============================================================

def compare_rankings():

    print("\nLoading real CVSS baseline...")
    cvss_df = pd.read_csv(CVSS_PATH)

    print(f"CVSS records: {len(cvss_df)}")

    print("\nLoading real VulnPilot-X priority results...")
    priority_df = pd.read_csv(PRIORITY_PATH)

    print(f"Priority records: {len(priority_df)}")

    # --------------------------------------------------------
    # Select required columns
    # --------------------------------------------------------

    cvss = cvss_df[
        [
            "cve_id",
            "cvss_rank",
            "cvss_score"
        ]
    ].copy()

    priority = priority_df[
        [
            "cve_id",
            "final_priority_rank",
            "contextual_risk_score",
            "priority"
        ]
    ].copy()

    # --------------------------------------------------------
    # Merge
    # --------------------------------------------------------

    comparison = pd.merge(
        cvss,
        priority,
        on="cve_id",
        how="inner"
    )

    print(
        f"\nCommon vulnerabilities evaluated: "
        f"{len(comparison)}"
    )

    # --------------------------------------------------------
    # Rank change
    # --------------------------------------------------------

    comparison["rank_change"] = (
        comparison["cvss_rank"]
        - comparison["final_priority_rank"]
    )

    comparison["absolute_rank_change"] = (
        comparison["rank_change"].abs()
    )

    # --------------------------------------------------------
    # Sort by VulnPilot-X ranking
    # --------------------------------------------------------

    comparison = comparison.sort_values(
        "final_priority_rank"
    ).reset_index(drop=True)

    # --------------------------------------------------------
    # Save detailed comparison
    # --------------------------------------------------------

    comparison.to_csv(
        OUTPUT_PATH,
        index=False
    )

    return comparison


# ============================================================
# Quantitative Metrics
# ============================================================

def calculate_metrics(comparison):

    cvss_ranks = comparison["cvss_rank"]
    contextual_ranks = comparison["final_priority_rank"]

    # --------------------------------------------------------
    # Spearman Rank Correlation
    # --------------------------------------------------------

    spearman_correlation, p_value = spearmanr(
        cvss_ranks,
        contextual_ranks
    )

    # --------------------------------------------------------
    # Mean Absolute Rank Change
    # --------------------------------------------------------

    mean_absolute_rank_change = (
        comparison["absolute_rank_change"].mean()
    )

    # --------------------------------------------------------
    # Median Absolute Rank Change
    # --------------------------------------------------------

    median_absolute_rank_change = (
        comparison["absolute_rank_change"].median()
    )

    # --------------------------------------------------------
    # Maximum Rank Change
    # --------------------------------------------------------

    maximum_rank_change = (
        comparison["absolute_rank_change"].max()
    )

    # --------------------------------------------------------
    # Number of changed rankings
    # --------------------------------------------------------

    changed_rankings = (
        comparison["rank_change"] != 0
    ).sum()

    total_records = len(comparison)

    percentage_changed = (
        changed_rankings / total_records
    ) * 100

    # --------------------------------------------------------
    # Top-K overlap
    # --------------------------------------------------------

    def top_k_overlap(k):

        cvss_top = set(
            comparison
            .nsmallest(k, "cvss_rank")["cve_id"]
        )

        contextual_top = set(
            comparison
            .nsmallest(k, "final_priority_rank")["cve_id"]
        )

        overlap = len(
            cvss_top.intersection(contextual_top)
        )

        return overlap

    top_10_overlap = top_k_overlap(
        min(10, total_records)
    )

    top_25_overlap = top_k_overlap(
        min(25, total_records)
    )

    top_50_overlap = top_k_overlap(
        min(50, total_records)
    )

    # --------------------------------------------------------
    # Priority distribution
    # --------------------------------------------------------

    priority_distribution = (
        comparison["priority"]
        .value_counts()
        .to_dict()
    )

    # --------------------------------------------------------
    # Create metrics table
    # --------------------------------------------------------

    metrics = pd.DataFrame(
        {
            "metric": [
                "Total vulnerabilities evaluated",
                "Spearman rank correlation",
                "Spearman p-value",
                "Mean absolute rank change",
                "Median absolute rank change",
                "Maximum absolute rank change",
                "Changed rankings",
                "Percentage of rankings changed",
                "Top-10 overlap",
                "Top-25 overlap",
                "Top-50 overlap",
                "Critical vulnerabilities",
                "High vulnerabilities",
                "Medium vulnerabilities",
                "Low vulnerabilities"
            ],

            "value": [
                total_records,
                round(spearman_correlation, 4),
                round(p_value, 6),
                round(mean_absolute_rank_change, 2),
                round(median_absolute_rank_change, 2),
                int(maximum_rank_change),
                int(changed_rankings),
                round(percentage_changed, 2),
                top_10_overlap,
                top_25_overlap,
                top_50_overlap,
                priority_distribution.get(
                    "Critical", 0
                ),
                priority_distribution.get(
                    "High", 0
                ),
                priority_distribution.get(
                    "Medium", 0
                ),
                priority_distribution.get(
                    "Low", 0
                )
            ]
        }
    )

    metrics.to_csv(
        METRICS_PATH,
        index=False
    )

    return metrics


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":

    comparison = compare_rankings()

    metrics = calculate_metrics(
        comparison
    )

    # --------------------------------------------------------
    # Display quantitative evaluation
    # --------------------------------------------------------

    print(
        "\n"
        + "=" * 70
    )

    print(
        "VulnPilot-X - Quantitative Evaluation"
    )

    print(
        "=" * 70
    )

    print(
        "\n=== Ranking Metrics ===\n"
    )

    print(
        metrics.to_string(index=False)
    )

    # --------------------------------------------------------
    # Show largest ranking changes
    # --------------------------------------------------------

    print(
        "\n=== Largest Ranking Changes ===\n"
    )

    largest_changes = comparison.sort_values(
        "absolute_rank_change",
        ascending=False
    ).head(20)

    print(
        largest_changes[
            [
                "cve_id",
                "cvss_rank",
                "final_priority_rank",
                "rank_change",
                "cvss_score",
                "contextual_risk_score",
                "priority"
            ]
        ].to_string(index=False)
    )

    print(
        "\nDetailed ranking comparison saved to:"
    )

    print(
        OUTPUT_PATH
    )

    print(
        "\nQuantitative evaluation saved to:"
    )

    print(
        METRICS_PATH
    )