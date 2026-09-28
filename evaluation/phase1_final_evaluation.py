import os
import pandas as pd
import numpy as np


# ============================================================
# VulnPilot-X — Final Phase-I Evaluation Consolidation
# ============================================================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROCESSED_DIR = os.path.join(BASE_DIR, "data", "processed")


def load_csv(filename):
    path = os.path.join(PROCESSED_DIR, filename)

    if not os.path.exists(path):
        raise FileNotFoundError(f"Missing file: {path}")

    return pd.read_csv(path)


def save_csv(df, filename):
    path = os.path.join(PROCESSED_DIR, filename)
    df.to_csv(path, index=False)
    print(f"[SAVED] {path}")


# ============================================================
# 1. DATASET VALIDATION
# ============================================================

def build_dataset_summary():
    df = load_csv("phase1_master_dataset.csv")

    total = len(df)
    epss_available = int(df["epss_available"].sum())
    epss_missing = total - epss_available
    kev_count = int(df["kev_status"].sum())

    summary = pd.DataFrame([
        {
            "metric": "Total CVEs",
            "value": total,
            "category": "Dataset"
        },
        {
            "metric": "CVSS available",
            "value": int(df["cvss_score"].notna().sum()),
            "category": "Dataset"
        },
        {
            "metric": "EPSS available",
            "value": epss_available,
            "category": "Exploitability"
        },
        {
            "metric": "EPSS unavailable",
            "value": epss_missing,
            "category": "Exploitability"
        },
        {
            "metric": "KEV cases",
            "value": kev_count,
            "category": "Exploitation Evidence"
        },
        {
            "metric": "KEV proportion (%)",
            "value": round(100 * kev_count / total, 2),
            "category": "Exploitation Evidence"
        }
    ])

    return summary


# ============================================================
# 2. BASELINE EVALUATION
# ============================================================

def build_baseline_summary():
    metrics = load_csv("phase1_independent_metrics.csv")

    rows = []

    for _, row in metrics.iterrows():

        strategy = row["strategy"]

        rows.append({
            "evaluation_type": "Independent KEV evaluation",
            "strategy": strategy,

            "precision_at_10": row["precision_at_10"],
            "recall_at_10": row["recall_at_10"],
            "f1_at_10": row["f1_at_10"],
            "ndcg_at_10": row["ndcg_at_10"],

            "precision_at_25": row["precision_at_25"],
            "recall_at_25": row["recall_at_25"],
            "f1_at_25": row["f1_at_25"],
            "ndcg_at_25": row["ndcg_at_25"],

            "precision_at_50": row["precision_at_50"],
            "recall_at_50": row["recall_at_50"],
            "f1_at_50": row["f1_at_50"],
            "ndcg_at_50": row["ndcg_at_50"],

            "precision_at_100": row["precision_at_100"],
            "recall_at_100": row["recall_at_100"],
            "f1_at_100": row["f1_at_100"],
            "ndcg_at_100": row["ndcg_at_100"]
        })

    return pd.DataFrame(rows)


# ============================================================
# 3. TEMPORAL HOLDOUT EVALUATION
# ============================================================

def build_temporal_summary():
    df = load_csv("phase1_temporal_holdout_summary.csv")

    df = df.copy()

    df.insert(
        0,
        "evaluation_type",
        "Temporal future holdout"
    )

    return df


# ============================================================
# 4. TOP-K COMPARISON
# ============================================================

def build_topk_comparison():

    df = load_csv("phase1_temporal_holdout_topk.csv")

    selected = df[
        df["top_k"].isin([10, 25, 50, 100])
    ].copy()

    selected = selected[
        [
            "strategy",
            "top_k",
            "holdout_records",
            "score_unavailable",
            "kev_count",
            "precision_at_k",
            "recall_at_k",
            "f1_at_k",
            "ndcg_at_k",
            "mean_cvss",
            "mean_epss"
        ]
    ]

    return selected


# ============================================================
# 5. VULNPILOT-X RANK MOVEMENT
# ============================================================

def build_rank_movement():

    df = load_csv("phase1_priority_results.csv")

    movement_counts = (
        df["rank_movement"]
        .value_counts()
        .rename_axis("rank_movement")
        .reset_index(name="count")
    )

    total = len(df)

    movement_counts["percentage"] = (
        movement_counts["count"] / total * 100
    ).round(2)

    return movement_counts


# ============================================================
# 6. PRIORITY DISTRIBUTION
# ============================================================

def build_priority_distribution():

    df = load_csv("phase1_context_analysis.csv")

    priority = (
        df["priority"]
        .value_counts()
        .rename_axis("priority")
        .reset_index(name="count")
    )

    priority["percentage"] = (
        priority["count"] / len(df) * 100
    ).round(2)

    return priority


# ============================================================
# 7. CONTEXT SENSITIVITY VALIDATION
# ============================================================

def build_context_validation():

    df = load_csv("phase1_context_sensitivity.csv")

    results = []

    for cve_id, group in df.groupby("cve_id"):

        group = group.sort_values("asset_criticality")

        scores = group["contextual_risk_score"].tolist()
        assets = group["asset_type"].tolist()

        monotonic = all(
            scores[i] <= scores[i + 1]
            for i in range(len(scores) - 1)
        )

        development_score = group.iloc[0]["contextual_risk_score"]
        public_score = group.iloc[-1]["contextual_risk_score"]

        results.append({
            "cve_id": cve_id,
            "asset_contexts_tested": len(group),
            "development_score": round(
                development_score, 2
            ),
            "public_facing_score": round(
                public_score, 2
            ),
            "risk_change": round(
                public_score - development_score, 2
            ),
            "monotonic_increase": monotonic,
            "validation_status": (
                "PASS" if monotonic else "FAIL"
            )
        })

    return pd.DataFrame(results)


# ============================================================
# 8. EXPLAINABILITY VALIDATION
# ============================================================

def build_explainability_validation():

    df = load_csv("phase1_explanation_results.csv")

    # Full precision validation.
    contribution_columns = [
        "cvss_contribution",
        "epss_contribution",
        "kev_contribution",
        "asset_contribution"
    ]

    for col in contribution_columns:
        df[col] = pd.to_numeric(
            df[col],
            errors="coerce"
        )

    df["contextual_risk_score"] = pd.to_numeric(
        df["contextual_risk_score"],
        errors="coerce"
    )

    contribution_sum = df[
        contribution_columns
    ].sum(axis=1)

    difference = (
        contribution_sum -
        df["contextual_risk_score"]
    ).abs()

    explanation_available = (
        df["explanation"]
        .fillna("")
        .str.strip()
        .ne("")
    )

    recommendation_available = (
        df["recommendation"]
        .fillna("")
        .str.strip()
        .ne("")
    )

    validation = pd.DataFrame([
        {
            "metric": "Total explanations",
            "value": len(df)
        },
        {
            "metric": "Explanation coverage (%)",
            "value": round(
                explanation_available.mean() * 100,
                2
            )
        },
        {
            "metric": "Recommendation coverage (%)",
            "value": round(
                recommendation_available.mean() * 100,
                2
            )
        },
        {
            "metric": "Maximum score verification error",
            "value": round(
                difference.max(),
                6
            )
        },
        {
            "metric": "Mean score verification error",
            "value": round(
                difference.mean(),
                6
            )
        },
        {
            "metric": "Rows within 0.01 tolerance (%)",
            "value": round(
                (difference <= 0.01).mean() * 100,
                2
            )
        }
    ])

    return validation


# ============================================================
# 9. MAIN
# ============================================================

def main():

    print("\n")
    print("=" * 70)
    print(" VulnPilot-X — FINAL PHASE-I EVALUATION")
    print("=" * 70)

    # --------------------------------------------------------
    # Dataset
    # --------------------------------------------------------

    dataset_summary = build_dataset_summary()

    save_csv(
        dataset_summary,
        "phase1_final_evaluation_summary.csv"
    )

    # --------------------------------------------------------
    # Baselines
    # --------------------------------------------------------

    baseline_summary = build_baseline_summary()

    save_csv(
        baseline_summary,
        "phase1_final_baseline_evaluation.csv"
    )

    # --------------------------------------------------------
    # Temporal holdout
    # --------------------------------------------------------

    temporal_summary = build_temporal_summary()

    save_csv(
        temporal_summary,
        "phase1_final_temporal_evaluation.csv"
    )

    # --------------------------------------------------------
    # Top-K
    # --------------------------------------------------------

    topk = build_topk_comparison()

    save_csv(
        topk,
        "phase1_final_topk_comparison.csv"
    )

    # --------------------------------------------------------
    # Rank movement
    # --------------------------------------------------------

    rank_movement = build_rank_movement()

    save_csv(
        rank_movement,
        "phase1_final_rank_movement.csv"
    )

    # --------------------------------------------------------
    # Priority distribution
    # --------------------------------------------------------

    priority = build_priority_distribution()

    save_csv(
        priority,
        "phase1_final_priority_distribution.csv"
    )

    # --------------------------------------------------------
    # Context sensitivity
    # --------------------------------------------------------

    context = build_context_validation()

    save_csv(
        context,
        "phase1_final_context_validation.csv"
    )

    # --------------------------------------------------------
    # Explainability
    # --------------------------------------------------------

    explainability = build_explainability_validation()

    save_csv(
        explainability,
        "phase1_final_explainability_validation.csv"
    )

    # ========================================================
    # CONSOLE SUMMARY
    # ========================================================

    print("\n")
    print("=" * 70)
    print(" FINAL PHASE-I SUMMARY")
    print("=" * 70)

    print("\n[DATASET]")
    print(dataset_summary.to_string(index=False))

    print("\n[BASELINE EVALUATION]")
    print(
        baseline_summary[
            [
                "strategy",
                "precision_at_100",
                "recall_at_100",
                "f1_at_100",
                "ndcg_at_100"
            ]
        ].to_string(index=False)
    )

    print("\n[TEMPORAL HOLDOUT]")
    print(
        temporal_summary[
            [
                "strategy",
                "precision_at_100",
                "recall_at_100",
                "f1_at_100",
                "ndcg_at_100"
            ]
        ].to_string(index=False)
    )

    print("\n[RANK MOVEMENT]")
    print(
        rank_movement.to_string(index=False)
    )

    print("\n[PRIORITY DISTRIBUTION]")
    print(
        priority.to_string(index=False)
    )

    print("\n[CONTEXT VALIDATION]")
    print(
        context.to_string(index=False)
    )

    print("\n[EXPLAINABILITY VALIDATION]")
    print(
        explainability.to_string(index=False)
    )

    print("\n")
    print("=" * 70)
    print(" FINAL PHASE-I EVALUATION COMPLETED")
    print("=" * 70)
    print("\n")


if __name__ == "__main__":
    main()