import os
import pandas as pd


# Project root directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Real NVD dataset
DATA_PATH = os.path.join(
    BASE_DIR,
    "data",
    "processed",
    "real_vulnerabilities.csv"
)

# Output file
OUTPUT_PATH = os.path.join(
    BASE_DIR,
    "data",
    "processed",
    "real_cvss_baseline.csv"
)


def run_cvss_baseline():

    print("\n=== VulnPilot-X: Real-World CVSS Baseline ===\n")

    # Load real NVD dataset
    df = pd.read_csv(DATA_PATH)

    print(f"Input records: {len(df)}")

    # Make sure CVSS is numeric
    df["cvss_score"] = pd.to_numeric(
        df["cvss_score"],
        errors="coerce"
    )

    # Remove records without valid CVSS
    df = df.dropna(
        subset=["cvss_score"]
    ).copy()

    # Rank vulnerabilities by CVSS score
    df["cvss_rank"] = (
        df["cvss_score"]
        .rank(
            method="min",
            ascending=False
        )
        .astype(int)
    )

    # Sort highest CVSS first
    ranked_df = df.sort_values(
        by=["cvss_score", "cve_id"],
        ascending=[False, True]
    ).reset_index(drop=True)

    # Display baseline results
    print(
        ranked_df[
            [
                "cvss_rank",
                "cve_id",
                "severity",
                "cvss_score",
                "cvss_version",
                "cwe_id"
            ]
        ]
        .head(20)
        .to_string(index=False)
    )

    print("\nShowing top 20 CVEs by CVSS.")

    # Save results
    ranked_df.to_csv(
        OUTPUT_PATH,
        index=False,
        encoding="utf-8"
    )

    print(
        f"\nReal CVSS baseline saved to:\n{OUTPUT_PATH}"
    )


if __name__ == "__main__":
    run_cvss_baseline()