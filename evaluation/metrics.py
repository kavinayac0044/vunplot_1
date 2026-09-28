import pandas as pd


# -----------------------------
# Configuration
# -----------------------------

INPUT_PATH = "data/processed/ranking_comparison.csv"
OUTPUT_PATH = "data/processed/evaluation_metrics.csv"


# -----------------------------
# Quantitative Evaluation
# -----------------------------

def calculate_metrics():

    df = pd.read_csv(INPUT_PATH)

    total = len(df)

    # Rank movement
    moved_up = (df["rank_change"] > 0).sum()
    moved_down = (df["rank_change"] < 0).sum()
    unchanged = (df["rank_change"] == 0).sum()
    changed = moved_up + moved_down

    # Rank statistics
    average_rank_change = df["rank_change"].mean()
    average_absolute_change = df["rank_change"].abs().mean()
    maximum_rank_change = df["rank_change"].abs().max()

    # Top-K overlap
    cvss_top3 = set(
        df.nsmallest(3, "cvss_rank")["cve_id"]
    )

    pilot_top3 = set(
        df.nsmallest(3, "final_priority_rank")["cve_id"]
    )

    top3_overlap = len(cvss_top3 & pilot_top3)

    cvss_top5 = set(
        df.nsmallest(5, "cvss_rank")["cve_id"]
    )

    pilot_top5 = set(
        df.nsmallest(5, "final_priority_rank")["cve_id"]
    )

    top5_overlap = len(cvss_top5 & pilot_top5)

    # Percentages
    changed_percentage = (changed / total) * 100
    unchanged_percentage = (unchanged / total) * 100

    top3_overlap_percentage = (top3_overlap / 3) * 100
    top5_overlap_percentage = (top5_overlap / 5) * 100

    # Create metrics table
    metrics = pd.DataFrame({
        "metric": [
            "Total vulnerabilities",
            "Rank changed",
            "Rank unchanged",
            "Moved higher",
            "Moved lower",
            "Rank changed percentage",
            "Rank unchanged percentage",
            "Average rank change",
            "Average absolute rank change",
            "Maximum absolute rank change",
            "Top-3 overlap",
            "Top-3 overlap percentage",
            "Top-5 overlap",
            "Top-5 overlap percentage",
        ],
        "value": [
            total,
            changed,
            unchanged,
            moved_up,
            moved_down,
            round(changed_percentage, 2),
            round(unchanged_percentage, 2),
            round(average_rank_change, 2),
            round(average_absolute_change, 2),
            maximum_rank_change,
            top3_overlap,
            round(top3_overlap_percentage, 2),
            top5_overlap,
            round(top5_overlap_percentage, 2),
        ],
    })

    metrics.to_csv(
        OUTPUT_PATH,
        index=False,
    )

    return metrics


# -----------------------------
# Main
# -----------------------------

if __name__ == "__main__":

    results = calculate_metrics()

    print("\n=== VulnPilot-X: Quantitative Evaluation ===\n")

    print(results.to_string(index=False))

    print(
        f"\nEvaluation metrics saved to: {OUTPUT_PATH}"
    )