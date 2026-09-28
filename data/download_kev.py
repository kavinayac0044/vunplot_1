import os
import json
import requests
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
    "real_vulnerabilities_enriched.csv"
)

OUTPUT_PATH = os.path.join(
    BASE_DIR,
    "data",
    "processed",
    "real_kev_status.csv"
)

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/"
    "feeds/known_exploited_vulnerabilities.json"
)


# ============================================================
# Download KEV Catalog
# ============================================================

def download_kev():

    print("=" * 70)
    print("VulnPilot-X - CISA KEV Data Collection")
    print("=" * 70)

    # --------------------------------------------------------
    # Load our vulnerability dataset
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

    # --------------------------------------------------------
    # Download CISA KEV catalog
    # --------------------------------------------------------

    print(
        "\nDownloading CISA KEV catalog..."
    )

    response = requests.get(
        KEV_URL,
        timeout=30
    )

    response.raise_for_status()

    kev_data = response.json()

    vulnerabilities = kev_data.get(
        "vulnerabilities",
        []
    )

    print(
        f"KEV catalog records: {len(vulnerabilities)}"
    )

    # --------------------------------------------------------
    # Extract KEV CVE IDs
    # --------------------------------------------------------

    kev_records = []

    for vulnerability in vulnerabilities:

        cve_id = vulnerability.get(
            "cveID"
        )

        if not cve_id:
            continue

        kev_records.append(
            {
                "cve_id": cve_id,
                "kev_status": 1,
                "vendor_project": vulnerability.get(
                    "vendorProject"
                ),
                "product": vulnerability.get(
                    "product"
                ),
                "vulnerability_name": vulnerability.get(
                    "vulnerabilityName"
                ),
                "date_added": vulnerability.get(
                    "dateAdded"
                ),
                "due_date": vulnerability.get(
                    "dueDate"
                ),
                "required_action": vulnerability.get(
                    "requiredAction"
                ),
                "known_ransomware_use": vulnerability.get(
                    "knownRansomwareCampaignUse"
                )
            }
        )

    kev_df = pd.DataFrame(
        kev_records
    )

    # --------------------------------------------------------
    # Merge KEV with our CVEs
    # --------------------------------------------------------

    result = df[
        ["cve_id"]
    ].copy()

    result = result.merge(
        kev_df,
        on="cve_id",
        how="left"
    )

    # --------------------------------------------------------
    # Mark non-KEV vulnerabilities
    # --------------------------------------------------------

    result["kev_status"] = (
        result["kev_status"]
        .fillna(0)
        .astype(int)
    )

    # --------------------------------------------------------
    # KEV source metadata
    # --------------------------------------------------------

    result["kev_source"] = (
        "CISA Known Exploited Vulnerabilities Catalog"
    )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    kev_count = (
        result["kev_status"] == 1
    ).sum()

    non_kev_count = (
        result["kev_status"] == 0
    ).sum()

    print("\n" + "=" * 70)
    print("KEV COLLECTION COMPLETED")
    print("=" * 70)

    print(
        f"\nTotal CVEs evaluated: {len(result)}"
    )

    print(
        f"Known Exploited Vulnerabilities: {kev_count}"
    )

    print(
        f"Not currently in KEV: {non_kev_count}"
    )

    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    result.to_csv(
        OUTPUT_PATH,
        index=False,
        encoding="utf-8"
    )

    print(
        f"\nOutput:\n{OUTPUT_PATH}"
    )

    # --------------------------------------------------------
    # Show KEV matches
    # --------------------------------------------------------

    print(
        "\nKEV matches in our dataset:"
    )

    matches = result[
        result["kev_status"] == 1
    ]

    if len(matches) > 0:

        print(
            matches[
                [
                    "cve_id",
                    "vendor_project",
                    "product",
                    "date_added",
                    "known_ransomware_use"
                ]
            ]
            .head(20)
            .to_string(index=False)
        )

    else:

        print(
            "No KEV matches found."
        )


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":

    download_kev()