import json
import os
import pandas as pd


# ============================================================
# Configuration
# ============================================================

BASE_DIR = os.path.dirname(__file__)

INPUT_FILE = os.path.join(
    BASE_DIR,
    "raw",
    "nvd_cves.json"
)

OUTPUT_DIR = os.path.join(
    BASE_DIR,
    "processed"
)

OUTPUT_FILE = os.path.join(
    OUTPUT_DIR,
    "real_vulnerabilities.csv"
)


# ============================================================
# CVSS Extraction
# ============================================================

def extract_cvss(metrics):
    """
    Extract the preferred available CVSS metric.

    Preference:
    CVSS v3.1 -> CVSS v3.0 -> CVSS v2
    """

    for version_key, version_name in [
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ]:

        metric_list = metrics.get(
            version_key,
            []
        )

        if not metric_list:
            continue

        metric = metric_list[0]

        cvss_data = metric.get(
            "cvssData",
            {}
        )

        score = cvss_data.get(
            "baseScore"
        )

        severity = cvss_data.get(
            "baseSeverity"
        )

        # CVSS v2 may store severity outside cvssData
        if severity is None:
            severity = metric.get(
                "baseSeverity"
            )

        # ====================================================
        # CVSS v2
        # ====================================================

        if version_name == "2.0":

            return {
                "cvss_score": score,
                "severity": severity,
                "cvss_version": version_name,

                # CVSS v2
                "attack_vector": cvss_data.get(
                    "accessVector"
                ),

                "attack_complexity": cvss_data.get(
                    "accessComplexity"
                ),

                "authentication": cvss_data.get(
                    "authentication"
                ),

                "confidentiality": cvss_data.get(
                    "confidentialityImpact"
                ),

                "integrity": cvss_data.get(
                    "integrityImpact"
                ),

                "availability": cvss_data.get(
                    "availabilityImpact"
                ),

                # Not available in CVSS v2
                "privileges_required": None,
                "user_interaction": None,
                "scope": None,
            }

        # ====================================================
        # CVSS v3.x
        # ====================================================

        return {
            "cvss_score": score,
            "severity": severity,
            "cvss_version": version_name,

            # CVSS v3.x
            "attack_vector": cvss_data.get(
                "attackVector"
            ),

            "attack_complexity": cvss_data.get(
                "attackComplexity"
            ),

            "privileges_required": cvss_data.get(
                "privilegesRequired"
            ),

            "user_interaction": cvss_data.get(
                "userInteraction"
            ),

            "scope": cvss_data.get(
                "scope"
            ),

            "confidentiality": cvss_data.get(
                "confidentialityImpact"
            ),

            "integrity": cvss_data.get(
                "integrityImpact"
            ),

            "availability": cvss_data.get(
                "availabilityImpact"
            ),

            # Not applicable to CVSS v3
            "authentication": None,
        }

    # ========================================================
    # No CVSS available
    # ========================================================

    return {
        "cvss_score": None,
        "severity": None,
        "cvss_version": "UNKNOWN",

        "attack_vector": None,
        "attack_complexity": None,
        "authentication": None,

        "privileges_required": None,
        "user_interaction": None,
        "scope": None,

        "confidentiality": None,
        "integrity": None,
        "availability": None,
    }


# ============================================================
# CWE Extraction
# ============================================================

def extract_cwe(weaknesses):

    for weakness in weaknesses:

        for description in weakness.get(
            "description",
            []
        ):

            value = description.get(
                "value"
            )

            if value:
                return value

    return "UNKNOWN"


# ============================================================
# Dataset Preparation
# ============================================================

def prepare_dataset():

    print("=" * 70)
    print("VulnPilot-X - Real NVD Dataset Preparation")
    print("=" * 70)

    # --------------------------------------------------------
    # Check input file
    # --------------------------------------------------------

    if not os.path.exists(INPUT_FILE):

        raise FileNotFoundError(
            f"NVD dataset not found:\n{INPUT_FILE}"
        )

    # --------------------------------------------------------
    # Load NVD dataset
    # --------------------------------------------------------

    print("\nLoading raw NVD dataset...")

    with open(
        INPUT_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        data = json.load(file)

    vulnerabilities = data.get(
        "vulnerabilities",
        []
    )

    print(
        f"Raw records loaded: {len(vulnerabilities)}"
    )

    rows = []

    # ========================================================
    # Process vulnerabilities
    # ========================================================

    for item in vulnerabilities:

        cve = item.get(
            "cve",
            {}
        )

        cve_id = cve.get(
            "id"
        )

        if not cve_id:
            continue

        # ----------------------------------------------------
        # Description
        # ----------------------------------------------------

        description = ""

        for desc in cve.get(
            "descriptions",
            []
        ):

            if desc.get("lang") == "en":

                description = desc.get(
                    "value",
                    ""
                )

                break

        # ----------------------------------------------------
        # CVSS
        # ----------------------------------------------------

        cvss_info = extract_cvss(
            cve.get(
                "metrics",
                {}
            )
        )

        # ----------------------------------------------------
        # CWE
        # ----------------------------------------------------

        cwe_id = extract_cwe(
            cve.get(
                "weaknesses",
                []
            )
        )

        # ----------------------------------------------------
        # Dates
        # ----------------------------------------------------

        published = cve.get(
            "published"
        )

        last_modified = cve.get(
            "lastModified"
        )

        # ----------------------------------------------------
        # Build row
        # ----------------------------------------------------

        row = {

            "cve_id": cve_id,

            "description": description,

            "cvss_score": cvss_info[
                "cvss_score"
            ],

            "severity": cvss_info[
                "severity"
            ],

            "cvss_version": cvss_info[
                "cvss_version"
            ],

            "cwe_id": cwe_id,

            # ----------------------------------------------
            # CVSS context metrics
            # ----------------------------------------------

            "attack_vector": cvss_info[
                "attack_vector"
            ],

            "attack_complexity": cvss_info[
                "attack_complexity"
            ],

            "authentication": cvss_info[
                "authentication"
            ],

            "privileges_required": cvss_info[
                "privileges_required"
            ],

            "user_interaction": cvss_info[
                "user_interaction"
            ],

            "scope": cvss_info[
                "scope"
            ],

            "confidentiality": cvss_info[
                "confidentiality"
            ],

            "integrity": cvss_info[
                "integrity"
            ],

            "availability": cvss_info[
                "availability"
            ],

            # ----------------------------------------------
            # Dates
            # ----------------------------------------------

            "published": published,

            "last_modified": last_modified,
        }

        rows.append(
            row
        )

    # ========================================================
    # Create DataFrame
    # ========================================================

    df = pd.DataFrame(
        rows
    )

    print(
        f"\nInitial extracted records: {len(df)}"
    )

    # ========================================================
    # Remove duplicate CVEs
    # ========================================================

    before_duplicates = len(df)

    df = df.drop_duplicates(
        subset=["cve_id"]
    )

    duplicates_removed = (
        before_duplicates
        - len(df)
    )

    # ========================================================
    # Numeric CVSS conversion
    # ========================================================

    df["cvss_score"] = pd.to_numeric(
        df["cvss_score"],
        errors="coerce"
    )

    # ========================================================
    # Remove invalid CVSS
    # ========================================================

    before_validation = len(df)

    df = df[
        df["cvss_score"].notna()
        & (df["cvss_score"] >= 0)
        & (df["cvss_score"] <= 10)
    ].copy()

    invalid_removed = (
        before_validation
        - len(df)
    )

    # ========================================================
    # Missing severity handling
    # ========================================================

    df["severity"] = df[
        "severity"
    ].fillna(
        "UNKNOWN"
    )

    # ========================================================
    # Missing CWE handling
    # ========================================================

    df["cwe_id"] = df[
        "cwe_id"
    ].fillna(
        "UNKNOWN"
    )

    # ========================================================
    # CVSS Ranking
    # ========================================================

    df = df.sort_values(
        by="cvss_score",
        ascending=False
    ).reset_index(
        drop=True
    )

    df["cvss_rank"] = range(
        1,
        len(df) + 1
    )

    # ========================================================
    # Save dataset
    # ========================================================

    os.makedirs(
        OUTPUT_DIR,
        exist_ok=True
    )

    df.to_csv(
        OUTPUT_FILE,
        index=False,
        encoding="utf-8"
    )

    # ========================================================
    # Summary
    # ========================================================

    print("\n" + "=" * 70)
    print("DATASET PREPARATION COMPLETED")
    print("=" * 70)

    print(
        f"\nRaw records: {len(vulnerabilities)}"
    )

    print(
        f"Duplicate CVEs removed: {duplicates_removed}"
    )

    print(
        f"Invalid/missing CVSS removed: {invalid_removed}"
    )

    print(
        f"Final valid records: {len(df)}"
    )

    print(
        f"\nOutput:\n{OUTPUT_FILE}"
    )

    # ========================================================
    # Columns
    # ========================================================

    print("\nColumns:")

    for column in df.columns:

        print(
            f" - {column}"
        )

    # ========================================================
    # CVSS Version Distribution
    # ========================================================

    print(
        "\nCVSS version distribution:"
    )

    print(
        df["cvss_version"]
        .value_counts()
        .to_string()
    )

    # ========================================================
    # Severity Distribution
    # ========================================================

    print(
        "\nSeverity distribution:"
    )

    print(
        df["severity"]
        .value_counts()
        .to_string()
    )

    # ========================================================
    # CVSS Statistics
    # ========================================================

    print(
        "\nCVSS statistics:"
    )

    print(
        df["cvss_score"]
        .describe()
        .to_string()
    )

    # ========================================================
    # Top 10
    # ========================================================

    print(
        "\nTop 10 vulnerabilities by CVSS:"
    )

    print(
        df[
            [
                "cvss_rank",
                "cve_id",
                "cvss_score",
                "severity",
                "cvss_version",
                "cwe_id"
            ]
        ]
        .head(10)
        .to_string(
            index=False
        )
    )


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":

    prepare_dataset()