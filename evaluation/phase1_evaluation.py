# evaluation/phase1_evaluation.py

import pandas as pd
import numpy as np
from pathlib import Path
from scipy.stats import spearmanr


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_FILE = BASE_DIR / "data" / "processed" / "phase1_baseline_rankings.csv"

OUTPUT_METRICS = BASE_DIR / "data" / "processed" / "phase1_evaluation_metrics.csv"
OUTPUT_CORRELATION = BASE_DIR / "data" / "processed" / "phase1_correlation_metrics.csv"
OUTPUT_MOVEMENT = BASE_DIR / "data" / "processed" / "phase1_rank_movement.csv"
OUTPUT_OVERLAP = BASE_DIR / "data" / "processed" / "phase1_topk_overlap.csv"
OUTPUT_CHARACTERISTICS = BASE_DIR / "data" / "processed" / "phase1_topk_characteristics.csv"


# ============================================================
# LOAD DATA
# ============================================================

print("=" * 70)
print("VulnPilot-X Phase 1 Evaluation")
print("=" * 70)

print("\nLoading baseline rankings...")

df = pd.read_csv(INPUT_FILE)

print(f"Records loaded: {len(df)}")
print(f"Columns: {len(df.columns)}")


# ============================================================
# STRATEGIES
# ============================================================

STRATEGIES = {
    "cvss_only": "score_cvss_only",
    "epss_only": "score_epss_only",
    "cvss_epss": "score_cvss_epss",
    "cvss_epss_kev": "score_cvss_epss_kev",
}


# ============================================================
# CREATE RANK COLUMNS
# ============================================================

print("\nCreating ranking columns...")

for strategy_name, score_column in STRATEGIES.items():

    rank_column = f"rank_{strategy_name}"

    df[rank_column] = (
        df[score_column]
        .rank(
            method="min",
            ascending=False,
            na_option="bottom"
        )
        .astype("Int64")
    )

    print(f"Created: {rank_column}")


# ============================================================
# BASIC INFORMATION
# ============================================================

print("\nDataset information:")
print(f"Total CVEs: {len(df)}")

if "kev_status" in df.columns:
    print(f"KEV cases: {int(df['kev_status'].sum())}")

if "epss_available" in df.columns:
    print(
        f"EPSS available: "
        f"{int(df['epss_available'].sum())}"
    )

    print(
        f"EPSS unavailable: "
        f"{int((df['epss_available'] == 0).sum())}"
    )


# ============================================================
# 1. SPEARMAN CORRELATION
# ============================================================

print("\n" + "=" * 70)
print("1. SPEARMAN RANK CORRELATION")
print("=" * 70)

correlation_results = []

baseline_rank = "rank_cvss_only"

for strategy_name in STRATEGIES:

    rank_column = f"rank_{strategy_name}"

    if strategy_name == "cvss_only":
        continue

    print(f"\nComparing CVSS-only vs {strategy_name}...")

    # Only rows where both ranks exist
    valid = df[
        df[baseline_rank].notna()
        & df[rank_column].notna()
    ].copy()

    if len(valid) < 2:

        correlation = np.nan
        p_value = np.nan

    else:

        # ----------------------------------------------------
        # Robust Spearman calculation
        # ----------------------------------------------------

        result = spearmanr(
            valid[baseline_rank].to_numpy(),
            valid[rank_column].to_numpy()
        )

        correlation = result.statistic
        p_value = result.pvalue

        # Convert numpy arrays/scalars safely
        correlation = float(
            np.asarray(correlation).reshape(-1)[0]
        )

        p_value = float(
            np.asarray(p_value).reshape(-1)[0]
        )

    print(f"Valid records: {len(valid)}")
    print(f"Spearman correlation: {correlation:.4f}")
    print(f"P-value: {p_value:.6f}")

    correlation_results.append(
        {
            "baseline": "cvss_only",
            "comparison": strategy_name,
            "valid_records": len(valid),
            "spearman_correlation": correlation,
            "p_value": p_value,
        }
    )


correlation_df = pd.DataFrame(correlation_results)

correlation_df.to_csv(
    OUTPUT_CORRELATION,
    index=False
)

print(
    f"\nSaved correlation results to:\n"
    f"{OUTPUT_CORRELATION}"
)


# ============================================================
# 2. RANK MOVEMENT
# ============================================================

print("\n" + "=" * 70)
print("2. RANK MOVEMENT")
print("=" * 70)

movement_results = []

for strategy_name in STRATEGIES:

    if strategy_name == "cvss_only":
        continue

    rank_column = f"rank_{strategy_name}"

    valid = df[
        df[baseline_rank].notna()
        & df[rank_column].notna()
    ].copy()

    # Rank difference
    valid["rank_difference"] = (
        valid[rank_column].astype(float)
        - valid[baseline_rank].astype(float)
    )

    # Absolute rank movement
    valid["absolute_rank_change"] = (
        valid["rank_difference"].abs()
    )

    mean_change = valid["absolute_rank_change"].mean()
    median_change = valid["absolute_rank_change"].median()
    max_change = valid["absolute_rank_change"].max()

    moved_up = (
        valid["rank_difference"] < 0
    ).sum()

    moved_down = (
        valid["rank_difference"] > 0
    ).sum()

    unchanged = (
        valid["rank_difference"] == 0
    ).sum()

    print(f"\n{strategy_name}")

    print(
        f"Mean absolute rank change: "
        f"{mean_change:.2f}"
    )

    print(
        f"Median absolute rank change: "
        f"{median_change:.2f}"
    )

    print(
        f"Maximum rank change: "
        f"{max_change:.0f}"
    )

    print(f"Moved up: {moved_up}")
    print(f"Moved down: {moved_down}")
    print(f"Unchanged: {unchanged}")

    movement_results.append(
        {
            "comparison": strategy_name,
            "valid_records": len(valid),
            "mean_absolute_rank_change": mean_change,
            "median_absolute_rank_change": median_change,
            "maximum_absolute_rank_change": max_change,
            "moved_up": int(moved_up),
            "moved_down": int(moved_down),
            "unchanged": int(unchanged),
        }
    )


movement_df = pd.DataFrame(movement_results)

movement_df.to_csv(
    OUTPUT_MOVEMENT,
    index=False
)

print(
    f"\nSaved rank movement results to:\n"
    f"{OUTPUT_MOVEMENT}"
)


# ============================================================
# 3. TOP-K OVERLAP
# ============================================================

print("\n" + "=" * 70)
print("3. TOP-K OVERLAP WITH CVSS-ONLY")
print("=" * 70)

TOP_K_VALUES = [10, 25, 50, 100]

overlap_results = []

# Sort CVSS baseline
cvss_sorted = df.sort_values(
    by=[
        "score_cvss_only",
        "cvss_score",
        "cve_id"
    ],
    ascending=[
        False,
        False,
        True
    ]
)

for strategy_name in STRATEGIES:

    if strategy_name == "cvss_only":
        continue

    score_column = STRATEGIES[strategy_name]

    strategy_sorted = df.sort_values(
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
    )

    print(f"\n{strategy_name}")

    for k in TOP_K_VALUES:

        baseline_top = set(
            cvss_sorted.head(k)["cve_id"]
        )

        strategy_top = set(
            strategy_sorted.head(k)["cve_id"]
        )

        overlap_count = len(
            baseline_top.intersection(strategy_top)
        )

        overlap_percentage = (
            overlap_count / k
        ) * 100

        print(
            f"Top-{k}: "
            f"{overlap_count}/{k} "
            f"({overlap_percentage:.2f}%)"
        )

        overlap_results.append(
            {
                "comparison": strategy_name,
                "top_k": k,
                "overlap_count": overlap_count,
                "overlap_percentage": overlap_percentage,
            }
        )


overlap_df = pd.DataFrame(overlap_results)

overlap_df.to_csv(
    OUTPUT_OVERLAP,
    index=False
)

print(
    f"\nSaved top-K overlap results to:\n"
    f"{OUTPUT_OVERLAP}"
)


# ============================================================
# 4. TOP-K CHARACTERISTICS
# ============================================================

print("\n" + "=" * 70)
print("4. TOP-K CHARACTERISTICS")
print("=" * 70)

characteristic_results = []

for strategy_name in STRATEGIES:

    score_column = STRATEGIES[strategy_name]

    strategy_sorted = df.sort_values(
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
    )

    print(f"\n{strategy_name}")

    for k in TOP_K_VALUES:

        top_k = strategy_sorted.head(k).copy()

        # ----------------------------------------------------
        # KEV coverage
        # ----------------------------------------------------

        if "kev_status" in top_k.columns:

            kev_coverage = (
                top_k["kev_status"].mean()
            ) * 100

        else:

            kev_coverage = np.nan

        # ----------------------------------------------------
        # CVSS statistics
        # ----------------------------------------------------

        mean_cvss = top_k["cvss_score"].mean()
        median_cvss = top_k["cvss_score"].median()

        # ----------------------------------------------------
        # EPSS statistics
        # ----------------------------------------------------

        if "epss_score" in top_k.columns:

            mean_epss = top_k["epss_score"].mean(
                skipna=True
            )

            median_epss = top_k["epss_score"].median(
                skipna=True
            )

            epss_available_count = (
                top_k["epss_score"]
                .notna()
                .sum()
            )

        else:

            mean_epss = np.nan
            median_epss = np.nan
            epss_available_count = 0

        print(
            f"Top-{k}: "
            f"KEV={kev_coverage:.2f}%, "
            f"Mean CVSS={mean_cvss:.2f}, "
            f"Mean EPSS={mean_epss:.4f}"
        )

        characteristic_results.append(
            {
                "strategy": strategy_name,
                "top_k": k,
                "kev_coverage_percentage": kev_coverage,
                "mean_cvss": mean_cvss,
                "median_cvss": median_cvss,
                "mean_epss": mean_epss,
                "median_epss": median_epss,
                "epss_available_count": int(
                    epss_available_count
                ),
            }
        )


characteristics_df = pd.DataFrame(
    characteristic_results
)

characteristics_df.to_csv(
    OUTPUT_CHARACTERISTICS,
    index=False
)

print(
    f"\nSaved top-K characteristics to:\n"
    f"{OUTPUT_CHARACTERISTICS}"
)


# ============================================================
# 5. COMBINED SUMMARY METRICS
# ============================================================

print("\n" + "=" * 70)
print("5. COMBINED EVALUATION SUMMARY")
print("=" * 70)

summary_results = []

for strategy_name in STRATEGIES:

    if strategy_name == "cvss_only":

        summary_results.append(
            {
                "strategy": strategy_name,
                "spearman_vs_cvss": 1.0,
                "mean_absolute_rank_change": 0.0,
                "median_absolute_rank_change": 0.0,
                "max_absolute_rank_change": 0.0,
                "top10_overlap_percentage": 100.0,
                "top25_overlap_percentage": 100.0,
                "top50_overlap_percentage": 100.0,
                "top100_overlap_percentage": 100.0,
            }
        )

        continue

    # --------------------------------------------------------
    # Correlation
    # --------------------------------------------------------

    corr_row = correlation_df[
        correlation_df["comparison"] == strategy_name
    ]

    if len(corr_row) > 0:

        spearman_value = corr_row[
            "spearman_correlation"
        ].iloc[0]

    else:

        spearman_value = np.nan

    # --------------------------------------------------------
    # Movement
    # --------------------------------------------------------

    movement_row = movement_df[
        movement_df["comparison"] == strategy_name
    ]

    if len(movement_row) > 0:

        mean_movement = movement_row[
            "mean_absolute_rank_change"
        ].iloc[0]

        median_movement = movement_row[
            "median_absolute_rank_change"
        ].iloc[0]

        max_movement = movement_row[
            "maximum_absolute_rank_change"
        ].iloc[0]

    else:

        mean_movement = np.nan
        median_movement = np.nan
        max_movement = np.nan

    # --------------------------------------------------------
    # Top-K overlap
    # --------------------------------------------------------

    strategy_overlap = overlap_df[
        overlap_df["comparison"] == strategy_name
    ]

    def get_overlap(k):

        row = strategy_overlap[
            strategy_overlap["top_k"] == k
        ]

        if len(row) == 0:
            return np.nan

        return row[
            "overlap_percentage"
        ].iloc[0]

    summary_results.append(
        {
            "strategy": strategy_name,
            "spearman_vs_cvss": spearman_value,
            "mean_absolute_rank_change": mean_movement,
            "median_absolute_rank_change": median_movement,
            "max_absolute_rank_change": max_movement,
            "top10_overlap_percentage": get_overlap(10),
            "top25_overlap_percentage": get_overlap(25),
            "top50_overlap_percentage": get_overlap(50),
            "top100_overlap_percentage": get_overlap(100),
        }
    )


summary_df = pd.DataFrame(summary_results)

summary_df.to_csv(
    OUTPUT_METRICS,
    index=False
)


# ============================================================
# PRINT FINAL SUMMARY
# ============================================================

print("\n")
print("=" * 70)
print("FINAL EVALUATION SUMMARY")
print("=" * 70)

print(
    summary_df.to_string(
        index=False,
        float_format=lambda x: f"{x:.4f}"
    )
)


print("\n" + "=" * 70)
print("FILES GENERATED")
print("=" * 70)

print(f"1. {OUTPUT_METRICS}")
print(f"2. {OUTPUT_CORRELATION}")
print(f"3. {OUTPUT_MOVEMENT}")
print(f"4. {OUTPUT_OVERLAP}")
print(f"5. {OUTPUT_CHARACTERISTICS}")

print("\nPhase 1 evaluation completed successfully.")
print("=" * 70)