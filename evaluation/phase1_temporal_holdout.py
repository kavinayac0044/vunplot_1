# evaluation/phase1_temporal_holdout.py

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

OUTPUT_SUMMARY = (
    BASE_DIR
    / "data"
    / "processed"
    / "phase1_temporal_holdout_summary.csv"
)

OUTPUT_TOPK = (
    BASE_DIR
    / "data"
    / "processed"
    / "phase1_temporal_holdout_topk.csv"
)

OUTPUT_SPLIT = (
    BASE_DIR
    / "data"
    / "processed"
    / "phase1_temporal_split_info.csv"
)


# ============================================================
# CONFIGURATION
# ============================================================

TRAIN_RATIO = 0.80

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

    if len(top_k_df) == 0:
        return np.nan

    return top_k_df["kev_status"].mean()


def recall_at_k(top_k_df, total_kev):

    if total_kev == 0:
        return np.nan

    return (
        top_k_df["kev_status"].sum()
        / total_kev
    )


def f1_score(precision, recall):

    if (
        pd.isna(precision)
        or pd.isna(recall)
        or (precision + recall) == 0
    ):
        return 0.0

    return (
        2 * precision * recall
        / (precision + recall)
    )


def dcg_at_k(relevances):

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

    relevances = np.asarray(
        relevances[:k]
    )

    if len(relevances) == 0:
        return np.nan

    actual_dcg = dcg_at_k(
        relevances
    )

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
# START
# ============================================================

print("=" * 70)
print("VulnPilot-X Phase 1 Temporal Holdout Evaluation")
print("=" * 70)


# ============================================================
# LOAD MASTER DATASET
# ============================================================

print("\nLoading Phase-1 master dataset...")

master_df = pd.read_csv(
    MASTER_FILE
)

print(
    f"Master records: {len(master_df)}"
)


# ============================================================
# LOAD RANKING DATASET
# ============================================================

print("\nLoading Phase-1 baseline rankings...")

ranking_df = pd.read_csv(
    RANKING_FILE
)

print(
    f"Ranking records: {len(ranking_df)}"
)


# ============================================================
# VALIDATE MASTER DATA
# ============================================================

required_master_columns = [
    "cve_id",
    "published",
    "cvss_score",
    "kev_status",
    "epss_score",
]

missing_master = [
    column
    for column in required_master_columns
    if column not in master_df.columns
]

if missing_master:

    raise ValueError(
        "Missing columns in master dataset: "
        + ", ".join(missing_master)
    )


# ============================================================
# VALIDATE RANKING DATA
# ============================================================

required_ranking_columns = [
    "cve_id",
    "score_cvss_only",
    "score_epss_only",
    "score_cvss_epss",
    "score_cvss_epss_kev",
]

missing_ranking = [
    column
    for column in required_ranking_columns
    if column not in ranking_df.columns
]

if missing_ranking:

    raise ValueError(
        "Missing columns in ranking dataset: "
        + ", ".join(missing_ranking)
    )


# ============================================================
# MERGE MASTER + RANKINGS
# ============================================================

print("\nMerging master data with baseline rankings...")

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


if len(df) != len(master_df):

    print(
        "Warning: merged record count differs "
        "from master dataset."
    )


# ============================================================
# CONVERT PUBLICATION DATE
# ============================================================

print("\nProcessing publication dates...")

df["published"] = pd.to_datetime(
    df["published"],
    errors="coerce",
    utc=True
)

invalid_dates = df["published"].isna().sum()

if invalid_dates > 0:

    print(
        f"Warning: {invalid_dates} records "
        f"have invalid publication dates."
    )

    df = df[
        df["published"].notna()
    ].copy()


# ============================================================
# SORT CHRONOLOGICALLY
# ============================================================

df = df.sort_values(
    by=[
        "published",
        "cve_id"
    ],
    ascending=[
        True,
        True
    ]
).reset_index(
    drop=True
)


# ============================================================
# TEMPORAL SPLIT
# ============================================================

total_records = len(df)

train_size = int(
    total_records * TRAIN_RATIO
)

holdout_size = (
    total_records - train_size
)

development_df = df.iloc[
    :train_size
].copy()

holdout_df = df.iloc[
    train_size:
].copy()


development_start = (
    development_df["published"].min()
)

development_end = (
    development_df["published"].max()
)

holdout_start = (
    holdout_df["published"].min()
)

holdout_end = (
    holdout_df["published"].max()
)


# ============================================================
# SPLIT INFORMATION
# ============================================================

print("\n" + "=" * 70)
print("TEMPORAL SPLIT")
print("=" * 70)

print(
    f"Development/reference records: "
    f"{len(development_df)}"
)

print(
    f"Holdout records: "
    f"{len(holdout_df)}"
)

print(
    f"\nDevelopment period:"
)

print(
    f"{development_start} → {development_end}"
)

print(
    f"\nHoldout period:"
)

print(
    f"{holdout_start} → {holdout_end}"
)


# ============================================================
# KEV DISTRIBUTION
# ============================================================

development_kev = int(
    development_df["kev_status"].sum()
)

holdout_kev = int(
    holdout_df["kev_status"].sum()
)

development_kev_rate = (
    development_kev
    / len(development_df)
)

holdout_kev_rate = (
    holdout_kev
    / len(holdout_df)
)


print("\n" + "=" * 70)
print("KEV DISTRIBUTION")
print("=" * 70)

print(
    f"Development KEV: "
    f"{development_kev} "
    f"({development_kev_rate * 100:.2f}%)"
)

print(
    f"Holdout KEV: "
    f"{holdout_kev} "
    f"({holdout_kev_rate * 100:.2f}%)"
)


# ============================================================
# SAVE SPLIT INFORMATION
# ============================================================

split_info = pd.DataFrame(
    [
        {
            "split": "development_reference",
            "records": len(development_df),
            "start_date": development_start,
            "end_date": development_end,
            "kev_count": development_kev,
            "kev_percentage":
                development_kev_rate * 100,
        },
        {
            "split": "temporal_holdout",
            "records": len(holdout_df),
            "start_date": holdout_start,
            "end_date": holdout_end,
            "kev_count": holdout_kev,
            "kev_percentage":
                holdout_kev_rate * 100,
        },
    ]
)

split_info.to_csv(
    OUTPUT_SPLIT,
    index=False
)


# ============================================================
# HOLDOUT EVALUATION
# ============================================================

print("\n" + "=" * 70)
print("HOLDOUT RANKING EVALUATION")
print("=" * 70)

topk_results = []
summary_results = []


for strategy_name, score_column in STRATEGIES.items():

    print(
        f"\nStrategy: {strategy_name}"
    )

    # --------------------------------------------------------
    # Remove rows where the strategy score is unavailable.
    #
    # Missing EPSS is NOT treated as zero.
    # --------------------------------------------------------

    available_df = holdout_df[
        holdout_df[score_column].notna()
    ].copy()

    unavailable_count = (
        len(holdout_df)
        - len(available_df)
    )

    print(
        f"Available scores: "
        f"{len(available_df)}"
    )

    print(
        f"Unavailable scores: "
        f"{unavailable_count}"
    )

    if len(available_df) == 0:
        continue


    # --------------------------------------------------------
    # Deterministic ranking
    # --------------------------------------------------------

    ranked_df = available_df.sort_values(
        by=[
            score_column,
            "cvss_score",
            "cve_id"
        ],
        ascending=[
            False,
            False,
            True
        ]
    ).reset_index(
        drop=True
    )


    total_available_kev = int(
        ranked_df["kev_status"].sum()
    )

    print(
        f"KEV available for evaluation: "
        f"{total_available_kev}"
    )


    # --------------------------------------------------------
    # Summary dictionary
    # --------------------------------------------------------

    strategy_summary = {
        "strategy": strategy_name,
        "holdout_records":
            len(ranked_df),
        "score_unavailable":
            unavailable_count,
        "holdout_kev_count":
            total_available_kev,
    }


    # --------------------------------------------------------
    # TOP-K
    # --------------------------------------------------------

    for k in TOP_K_VALUES:

        actual_k = min(
            k,
            len(ranked_df)
        )

        top_k_df = ranked_df.head(
            actual_k
        )


        precision = precision_at_k(
            top_k_df
        )

        recall = recall_at_k(
            top_k_df,
            total_available_kev
        )

        f1 = f1_score(
            precision,
            recall
        )


        relevances = (
            ranked_df[
                "kev_status"
            ].to_numpy()
        )

        ndcg = ndcg_at_k(
            relevances,
            actual_k
        )


        kev_count = int(
            top_k_df[
                "kev_status"
            ].sum()
        )


        mean_cvss = (
            top_k_df[
                "cvss_score"
            ].mean()
        )


        mean_epss = (
            top_k_df[
                "epss_score"
            ].mean(
                skipna=True
            )
        )


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
                "strategy":
                    strategy_name,

                "top_k":
                    k,

                "actual_k":
                    actual_k,

                "holdout_records":
                    len(ranked_df),

                "score_unavailable":
                    unavailable_count,

                "kev_count":
                    kev_count,

                "precision_at_k":
                    precision,

                "recall_at_k":
                    recall,

                "f1_at_k":
                    f1,

                "ndcg_at_k":
                    ndcg,

                "mean_cvss":
                    mean_cvss,

                "mean_epss":
                    mean_epss,
            }
        )


        strategy_summary[
            f"precision_at_{k}"
        ] = precision

        strategy_summary[
            f"recall_at_{k}"
        ] = recall

        strategy_summary[
            f"f1_at_{k}"
        ] = f1

        strategy_summary[
            f"ndcg_at_{k}"
        ] = ndcg


    summary_results.append(
        strategy_summary
    )


# ============================================================
# SAVE RESULTS
# ============================================================

topk_df = pd.DataFrame(
    topk_results
)

summary_df = pd.DataFrame(
    summary_results
)


topk_df.to_csv(
    OUTPUT_TOPK,
    index=False
)

summary_df.to_csv(
    OUTPUT_SUMMARY,
    index=False
)


# ============================================================
# FINAL SUMMARY
# ============================================================

print("\n" + "=" * 70)
print("FINAL TEMPORAL HOLDOUT SUMMARY")
print("=" * 70)

if len(summary_df) > 0:

    print(
        summary_df.to_string(
            index=False,
            float_format=lambda x:
                f"{x:.4f}"
        )
    )

else:

    print(
        "No strategy could be evaluated."
    )


# ============================================================
# OUTPUT FILES
# ============================================================

print("\n" + "=" * 70)
print("FILES GENERATED")
print("=" * 70)

print(
    f"1. {OUTPUT_SPLIT}"
)

print(
    f"2. {OUTPUT_TOPK}"
)

print(
    f"3. {OUTPUT_SUMMARY}"
)

print("\n" + "=" * 70)

print(
    "Temporal holdout evaluation completed successfully."
)

print("=" * 70)