import os
import requests
import pandas as pd
import time


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
    "real_vulnerabilities.csv"
)

OUTPUT_PATH = os.path.join(
    BASE_DIR,
    "data",
    "processed",
    "real_epss_scores.csv"
)

EPSS_API = "https://api.first.org/data/v1/epss"

# Number of CVEs sent in one API request
BATCH_SIZE = 100


# ============================================================
# Fetch EPSS for a batch of CVEs
# ============================================================

def get_epss_batch(cve_ids):

    try:

        response = requests.get(
            EPSS_API,
            params={
                "cve": ",".join(cve_ids)
            },
            timeout=30
        )

        response.raise_for_status()

        data = response.json()

        return data.get(
            "data",
            []
        )

    except Exception as error:

        print(
            f"Batch request failed: {error}"
        )

        return []


# ============================================================
# Main
# ============================================================

def download_epss():

    print("=" * 70)
    print("VulnPilot-X - Batch EPSS Data Collection")
    print("=" * 70)

    # --------------------------------------------------------
    # Load dataset
    # --------------------------------------------------------

    if not os.path.exists(INPUT_PATH):

        raise FileNotFoundError(
            f"Input dataset not found:\n{INPUT_PATH}"
        )

    df = pd.read_csv(
        INPUT_PATH
    )

    print(
        f"\nInput vulnerabilities: {len(df)}"
    )

    cve_ids = (
        df["cve_id"]
        .dropna()
        .astype(str)
        .tolist()
    )

    # --------------------------------------------------------
    # Test API with first CVE
    # --------------------------------------------------------

    test_cve = cve_ids[0]

    print(
        f"\nTesting EPSS API with: {test_cve}"
    )

    test_results = get_epss_batch(
        [test_cve]
    )

    if not test_results:

        raise RuntimeError(
            "EPSS API test failed."
        )

    print(
        f"EPSS: {test_results[0].get('epss')}"
    )

    print(
        f"Percentile: {test_results[0].get('percentile')}"
    )

    print(
        "\nEPSS API test successful."
    )

    # --------------------------------------------------------
    # Download batches
    # --------------------------------------------------------

    results = []

    total = len(cve_ids)

    print(
        "\nDownloading EPSS scores in batches..."
    )

    for start in range(
        0,
        total,
        BATCH_SIZE
    ):

        batch = cve_ids[
            start:start + BATCH_SIZE
        ]

        batch_results = get_epss_batch(
            batch
        )

        # Create lookup
        lookup = {}

        for record in batch_results:

            cve_id = record.get(
                "cve"
            )

            if cve_id:

                lookup[cve_id] = {
                    "epss_score": record.get(
                        "epss"
                    ),
                    "epss_percentile": record.get(
                        "percentile"
                    )
                }

        # ----------------------------------------------------
        # Preserve every CVE
        # ----------------------------------------------------

        for cve_id in batch:

            record = lookup.get(
                cve_id,
                {}
            )

            results.append(
                {
                    "cve_id": cve_id,

                    "epss_score": record.get(
                        "epss_score"
                    ),

                    "epss_percentile": record.get(
                        "epss_percentile"
                    )
                }
            )

        processed = min(
            start + BATCH_SIZE,
            total
        )

        print(
            f"Processed: {processed}/{total}"
        )

        # Small delay between batches
        time.sleep(0.5)

    # --------------------------------------------------------
    # Create DataFrame
    # --------------------------------------------------------

    epss_df = pd.DataFrame(
        results
    )

    # --------------------------------------------------------
    # Numeric conversion
    # --------------------------------------------------------

    epss_df["epss_score"] = pd.to_numeric(
        epss_df["epss_score"],
        errors="coerce"
    )

    epss_df["epss_percentile"] = pd.to_numeric(
        epss_df["epss_percentile"],
        errors="coerce"
    )

    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    epss_df.to_csv(
        OUTPUT_PATH,
        index=False,
        encoding="utf-8"
    )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    available = (
        epss_df["epss_score"]
        .notna()
        .sum()
    )

    missing = (
        epss_df["epss_score"]
        .isna()
        .sum()
    )

    print("\n" + "=" * 70)
    print("EPSS COLLECTION COMPLETED")
    print("=" * 70)

    print(
        f"\nTotal CVEs: {len(epss_df)}"
    )

    print(
        f"EPSS available: {available}"
    )

    print(
        f"EPSS missing: {missing}"
    )

    print(
        f"\nOutput:\n{OUTPUT_PATH}"
    )

    # --------------------------------------------------------
    # Show sample
    # --------------------------------------------------------

    print(
        "\nSample EPSS results:"
    )

    print(
        epss_df
        .head(10)
        .to_string(index=False)
    )


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":

    download_epss()