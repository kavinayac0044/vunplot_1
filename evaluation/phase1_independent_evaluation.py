# evaluation/phase1_independent_evaluation.py

import pandas as pd
import numpy as np
from pathlib import Path


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

MASTER_FILE = (
    BASE_DIR
    / "data"
    / "processed"
    / "phase1_master_dataset.csv"
)

RANKING_FILE = (
    BASE_DIR
    / "data"
    / "processed"
    / "phase1_baseline_rankings.csv"
)

OUTPUT_METRICS = (
    BASE_DIR
    / "data"
    / "processed"
    / "phase1_independent_metrics.csv"
)

OUTPUT_TOPK = (
    BASE_DIR
    / "data"
    / "processed"
    / "phase1_independent_topk.csv"
)

OUTPUT_ENRICHMENT = (
    BASE_DIR
    / "data"
    / "processed"
    / "phase1_kev_enrichment.csv"
)


# ============================================================
# CONFIGURATION
# ============================================================

TOP_K_VALUES = [10, 25, 50, 100]

STRATEGIES = {
    "cvss_only": "score_cvss_only",
    "epss_only": "score_epss_only",
    "cvss_epss": "score_cvss_epss",
    "cvss_epss_kev": "score_cvss_epss_kev",
}


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def precision_at_k(top_k_df):
    """
    Precision@K:
    Fraction of vulnerabilities in Top-K that are KEV.
    """

    if len(top_k_df) == 0:
        return np.nan

    return top_k_df["kev_status"].mean()


def recall_at_k(top_k_df, total_kev):
    """
    Recall@K:
    Fraction of all KEV vulnerabilities captured in Top-K.
    """

    if total_kev == 0:
        return np.nan

    return top_k_df["kev_status"].sum() / total_kev


def f1_score(precision, recall):
    """
    F1 score from Precision and Recall.
    """

    if (
        pd.isna(precision)
        or pd.isna(recall)
        or (precision + recall) == 0
    ):
        return 0.0

    return (
        2
        * precision
        * recall
        / (precision + recall)
    )


def dcg_at_k(relevances):
    """
    Discounted Cumulative Gain.
    """

    relevances = np.asarray(relevances)

    if len(relevances) == 0:
        return 0.0

    discounts = np.log2(
        np.arange(2, len(relevances) + 2)
    )

    return np.sum(
        relevances / discounts
    )


def ndcg_at_k(relevances, k):
    """
    Normalized Discounted Cumulative Gain.

    KEV = relevance 1
    Non-KEV = relevance 0
    """

    relevances = np.asarray(
        relevances[:k]
    )

    if len(relevances) == 0:
        return np.nan

    actual_dcg = dcg_at_k(relevances)

    ideal_relevances = np.sort(
        relevances
    )[::-1]

    ideal_dcg = dcg_at_k(
        ideal_relevances
    )

    if ideal_dcg == 0:
        return 0.0

    return actual_dcg / ideal_dcg


# ============================================================
# LOAD DATA
# ============================================================

print("=" * 70)
print("VulnPilot-X Phase 1 Independent Evaluation")
print("=" * 70)

print("\nLoading datasets...")

master_df = pd.read_csv(
    MASTER_FILE
)

ranking_df = pd.read_csv(
    RANKING_FILE
)

print(
    f"Master dataset records: {len(master_df)}"
)

print(
    f"Ranking dataset records: {len(ranking_df)}"
)


# ============================================================
# MERGE
# ============================================================

print("\nMerging master dataset with ranking data...")

required_master_columns = [
    "cve_id",
    "cvss_score",
    "kev_status",
]

for column in required_master_columns:

    if column not in master_df.columns:
        raise ValueError(
            f"Missing column in master dataset: {column}"
        )


required_ranking_columns = [
    "cve_id",
    "score_cvss_only",
    "score_epss_only",
    "score_cvss_epss",
    "score_cvss_epss_kev",
]

for column in required_ranking_columns:

    if column not in ranking_df.columns:
        raise ValueError(
            f"Missing column in ranking dataset: {column}"
        )


df = master_df.merge(
    ranking_df[
        required_ranking_columns
    ],
    on="cve_id",
    how="inner"
)

print(
    f"Merged records: {len(df)}"
)


# ============================================================
# BASIC DATA VALIDATION
# ============================================================

print("\n" + "=" * 70)
print("DATA VALIDATION")
print("=" * 70)

total_records = len(df)

total_kev = int(
    df["kev_status"].sum()
)

kev_prevalence = (
    total_kev / total_records
)

print(
    f"Total vulnerabilities: {total_records}"
)

print(
    f"Known Exploited Vulnerabilities (KEV): "
    f"{total_kev}"
)

print(
    f"KEV prevalence in experimental sample: "
    f"{kev_prevalence * 100:.2f}%"
)

print(
    "\nIMPORTANT:"
)

print(
    "This Phase-1 dataset is KEV-enriched because "
    "all identified KEV cases were retained."
)

print(
    "Therefore KEV-based metrics are descriptive "
    "for this experimental subset and should not "
    "be interpreted as population-level performance."
)


# ============================================================
# CREATE RANKINGS
# ============================================================

for strategy_name, score_column in STRATEGIES.items():

    rank_column = f"rank_{strategy_name}"

    # Rank available scores only.
    # Missing EPSS-derived scores remain missing instead of being
    # incorrectly treated as zero exploitability.
    df[rank_column] = (
        df[score_column]
        .rank(
            method="first",
            ascending=False,
            na_option="keep"
        )
        .astype("Int64")
    )

    available_count = df[score_column].notna().sum()
    missing_count = df[score_column].isna().sum()

    print(
        f"{strategy_name}: "
        f"{available_count} ranked, "
        f"{missing_count} unavailable"
    )

# ============================================================
# TOP-K INDEPENDENT EVALUATION
# ============================================================

print("\n" + "=" * 70)
print("TOP-K INDEPENDENT EVALUATION")
print("=" * 70)

topk_results = []

for strategy_name, score_column in STRATEGIES.items():

    print(
        f"\nStrategy: {strategy_name}"
    )

    ranked_df = df.sort_values(
        by=[
            score_column,
            "cvss_score",
            "cve_id",
        ],
        ascending=[
            False,
            False,
            True,
        ],
    ).reset_index(
        drop=True
    )

    for k in TOP_K_VALUES:

        top_k_df = ranked_df.head(k)

        precision = precision_at_k(
            top_k_df
        )

        recall = recall_at_k(
            top_k_df,
            total_kev
        )

        f1 = f1_score(
            precision,
            recall
        )

        relevances = (
            ranked_df["kev_status"]
            .to_numpy()
        )

        ndcg = ndcg_at_k(
            relevances,
            k
        )

        kev_count = int(
            top_k_df["kev_status"].sum()
        )

        mean_cvss = (
            top_k_df["cvss_score"]
            .mean()
        )

        # EPSS may contain missing values
        if "epss_score" in top_k_df.columns:

            mean_epss = (
                top_k_df["epss_score"]
                .mean(
                    skipna=True
                )
            )

        else:

            mean_epss = np.nan

        print(
            f"Top-{k}: "
            f"KEV={kev_count}, "
            f"Precision={precision:.4f}, "
            f"Recall={recall:.4f}, "
            f"F1={f1:.4f}, "
            f"NDCG={ndcg:.4f}"
        )

        topk_results.append(
            {
                "strategy": strategy_name,
                "top_k": k,
                "kev_count": kev_count,
                "precision_at_k": precision,
                "recall_at_k": recall,
                "f1_at_k": f1,
                "ndcg_at_k": ndcg,
                "mean_cvss": mean_cvss,
                "mean_epss": mean_epss,
            }
        )


topk_df = pd.DataFrame(
    topk_results
)

topk_df.to_csv(
    OUTPUT_TOPK,
    index=False
)

print(
    f"\nSaved Top-K metrics to:"
)

print(
    OUTPUT_TOPK
)


# ============================================================
# KEV ENRICHMENT
# ============================================================

print("\n" + "=" * 70)
print("KEV ENRICHMENT ANALYSIS")
print("=" * 70)

enrichment_results = []

baseline_prevalence = (
    df["kev_status"].mean()
)

for strategy_name, score_column in STRATEGIES.items():

    ranked_df = df.sort_values(
        by=[
            score_column,
            "cvss_score",
            "cve_id",
        ],
        ascending=[
            False,
            False,
            True,
        ]
    ).reset_index(
        drop=True
    )

    for k in TOP_K_VALUES:

        top_k_df = ranked_df.head(k)

        topk_prevalence = (
            top_k_df["kev_status"]
            .mean()
        )

        if baseline_prevalence > 0:

            enrichment_ratio = (
                topk_prevalence
                / baseline_prevalence
            )

        else:

            enrichment_ratio = np.nan

        enrichment_results.append(
            {
                "strategy": strategy_name,
                "top_k": k,
                "overall_kev_prevalence":
                    baseline_prevalence,
                "topk_kev_prevalence":
                    topk_prevalence,
                "enrichment_ratio":
                    enrichment_ratio,
            }
        )

        print(
            f"{strategy_name} Top-{k}: "
            f"KEV prevalence="
            f"{topk_prevalence * 100:.2f}%, "
            f"enrichment="
            f"{enrichment_ratio:.2f}x"
        )


enrichment_df = pd.DataFrame(
    enrichment_results
)

enrichment_df.to_csv(
    OUTPUT_ENRICHMENT,
    index=False
)

print(
    f"\nSaved enrichment analysis to:"
)

print(
    OUTPUT_ENRICHMENT
)


# ============================================================
# SUMMARY METRICS
# ============================================================

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)

summary_results = []

for strategy_name in STRATEGIES:

    strategy_rows = topk_df[
        topk_df["strategy"]
        == strategy_name
    ]

    def get_metric(
        k,
        column
    ):

        row = strategy_rows[
            strategy_rows["top_k"] == k
        ]

        if len(row) == 0:
            return np.nan

        return row[column].iloc[0]

    summary_results.append(
        {
            "strategy": strategy_name,

            "precision_at_10":
                get_metric(
                    10,
                    "precision_at_k"
                ),

            "recall_at_10":
                get_metric(
                    10,
                    "recall_at_k"
                ),

            "f1_at_10":
                get_metric(
                    10,
                    "f1_at_k"
                ),

            "ndcg_at_10":
                get_metric(
                    10,
                    "ndcg_at_k"
                ),

            "precision_at_25":
                get_metric(
                    25,
                    "precision_at_k"
                ),

            "recall_at_25":
                get_metric(
                    25,
                    "recall_at_k"
                ),

            "f1_at_25":
                get_metric(
                    25,
                    "f1_at_k"
                ),

            "ndcg_at_25":
                get_metric(
                    25,
                    "ndcg_at_k"
                ),

            "precision_at_50":
                get_metric(
                    50,
                    "precision_at_k"
                ),

            "recall_at_50":
                get_metric(
                    50,
                    "recall_at_k"
                ),

            "f1_at_50":
                get_metric(
                    50,
                    "f1_at_k"
                ),

            "ndcg_at_50":
                get_metric(
                    50,
                    "ndcg_at_k"
                ),

            "precision_at_100":
                get_metric(
                    100,
                    "precision_at_k"
                ),

            "recall_at_100":
                get_metric(
                    100,
                    "recall_at_k"
                ),

            "f1_at_100":
                get_metric(
                    100,
                    "f1_at_k"
                ),

            "ndcg_at_100":
                get_metric(
                    100,
                    "ndcg_at_k"
                ),
        }
    )


summary_df = pd.DataFrame(
    summary_results
)

summary_df.to_csv(
    OUTPUT_METRICS,
    index=False
)


# ============================================================
# PRINT FINAL TABLE
# ============================================================

print(
    "\n" + "=" * 70
)

print(
    "FINAL INDEPENDENT EVALUATION"
)

print(
    "=" * 70
)

print(
    summary_df.to_string(
        index=False,
        float_format=lambda x: f"{x:.4f}"
    )
)


# ============================================================
# OUTPUT FILES
# ============================================================

print(
    "\n" + "=" * 70
)

print(
    "FILES GENERATED"
)

print(
    "=" * 70
)

print(
    f"1. {OUTPUT_METRICS}"
)

print(
    f"2. {OUTPUT_TOPK}"
)

print(
    f"3. {OUTPUT_ENRICHMENT}"
)

print(
    "\nPhase 1 independent evaluation completed successfully."
)

print(
    "=" * 70
)