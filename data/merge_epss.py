import os
import pandas as pd


# ============================================================
# Configuration
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

VULNERABILITY_PATH = os.path.join(
    BASE_DIR,
    "data",
    "processed",
    "real_vulnerabilities.csv"
)

EPSS_PATH = os.path.join(
    BASE_DIR,
    "data",
    "processed",
    "real_epss_scores.csv"
)

OUTPUT_PATH = os.path.join(
    BASE_DIR,
    "data",
    "processed",
    "real_vulnerabilities_enriched.csv"
)


# ============================================================
# Merge EPSS
# ============================================================

def merge_epss():

    print("=" * 70)
    print("VulnPilot-X - NVD + EPSS Dataset Enrichment")
    print("=" * 70)

    # --------------------------------------------------------
    # Load NVD dataset
    # --------------------------------------------------------

    if not os.path.exists(VULNERABILITY_PATH):

        raise FileNotFoundError(
            f"NVD dataset not found:\n{VULNERABILITY_PATH}"
        )

    vulnerabilities = pd.read_csv(
        VULNERABILITY_PATH
    )

    print(
        f"\nNVD records: {len(vulnerabilities)}"
    )

    # --------------------------------------------------------
    # Load EPSS dataset
    # --------------------------------------------------------

    if not os.path.exists(EPSS_PATH):

        raise FileNotFoundError(
            f"EPSS dataset not found:\n{EPSS_PATH}"
        )

    epss = pd.read_csv(
        EPSS_PATH
    )

    print(
        f"EPSS records: {len(epss)}"
    )

    # --------------------------------------------------------
    # Check duplicate CVEs
    # --------------------------------------------------------

    duplicate_epss = epss[
        epss["cve_id"].duplicated()
    ]

    if len(duplicate_epss) > 0:

        print(
            f"\nDuplicate EPSS CVEs found: "
            f"{len(duplicate_epss)}"
        )

        epss = epss.drop_duplicates(
            subset=["cve_id"],
            keep="first"
        )

    # --------------------------------------------------------
    # Merge
    # --------------------------------------------------------

    enriched = vulnerabilities.merge(
        epss[
            [
                "cve_id",
                "epss_score",
                "epss_percentile"
            ]
        ],
        on="cve_id",
        how="left",
        validate="one_to_one"
    )

    # --------------------------------------------------------
    # Convert EPSS values to numeric
    # --------------------------------------------------------

    enriched["epss_score"] = pd.to_numeric(
        enriched["epss_score"],
        errors="coerce"
    )

    enriched["epss_percentile"] = pd.to_numeric(
        enriched["epss_percentile"],
        errors="coerce"
    )

    # --------------------------------------------------------
    # Validation
    # --------------------------------------------------------

    missing_epss = (
        enriched["epss_score"]
        .isna()
        .sum()
    )

    print(
        f"\nEnriched records: {len(enriched)}"
    )

    print(
        f"Missing EPSS values: {missing_epss}"
    )

    if len(enriched) != len(vulnerabilities):

        raise RuntimeError(
            "Record count changed after EPSS merge."
        )

    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    enriched.to_csv(
        OUTPUT_PATH,
        index=False,
        encoding="utf-8"
    )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("EPSS ENRICHMENT COMPLETED")
    print("=" * 70)

    print(
        f"\nFinal records: {len(enriched)}"
    )

    print(
        f"EPSS available: "
        f"{enriched['epss_score'].notna().sum()}"
    )

    print(
        f"EPSS missing: "
        f"{enriched['epss_score'].isna().sum()}"
    )

    print(
        f"\nOutput:\n{OUTPUT_PATH}"
    )

    # --------------------------------------------------------
    # Sample
    # --------------------------------------------------------

    print(
        "\nSample enriched records:"
    )

    print(
        enriched[
            [
                "cve_id",
                "cvss_score",
                "cvss_version",
                "epss_score",
                "epss_percentile"
            ]
        ]
        .head(10)
        .to_string(index=False)
    )


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":

    merge_epss()