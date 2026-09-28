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
    "raw",
    "nvd_recent_cves.json"
)

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/"
    "feeds/known_exploited_vulnerabilities.json"
)


# ============================================================
# Load NVD dataset
# ============================================================

print("=" * 70)
print("VulnPilot-X - Recent Dataset KEV Analysis")
print("=" * 70)

with open(
    INPUT_PATH,
    "r",
    encoding="utf-8"
) as f:

    nvd_data = json.load(f)


nvd_records = nvd_data.get(
    "vulnerabilities",
    []
)

nvd_cves = set()

for item in nvd_records:

    cve_id = item.get(
        "cve",
        {}
    ).get(
        "id"
    )

    if cve_id:
        nvd_cves.add(cve_id)


print(
    f"\nRecent NVD CVEs: {len(nvd_cves)}"
)


# ============================================================
# Download CISA KEV
# ============================================================

print(
    "\nDownloading CISA KEV catalog..."
)

response = requests.get(
    KEV_URL,
    timeout=60
)

response.raise_for_status()

kev_data = response.json()

kev_records = kev_data.get(
    "vulnerabilities",
    []
)

kev_cves = set()

for item in kev_records:

    cve_id = item.get(
        "cveID"
    )

    if cve_id:
        kev_cves.add(cve_id)


print(
    f"CISA KEV CVEs: {len(kev_cves)}"
)


# ============================================================
# Find overlap
# ============================================================

overlap = sorted(
    nvd_cves.intersection(
        kev_cves
    )
)


print("\n" + "=" * 70)
print("KEV OVERLAP RESULT")
print("=" * 70)

print(
    f"\nRecent NVD CVEs : {len(nvd_cves)}"
)

print(
    f"KEV CVEs        : {len(kev_cves)}"
)

print(
    f"KEV overlap     : {len(overlap)}"
)

if len(nvd_cves) > 0:

    percentage = (
        len(overlap)
        / len(nvd_cves)
        * 100
    )

    print(
        f"KEV percentage  : {percentage:.2f}%"
    )


# ============================================================
# Show sample matches
# ============================================================

if overlap:

    print(
        "\nSample KEV matches:"
    )

    for cve in overlap[:30]:

        print(
            f"  {cve}"
        )

else:

    print(
        "\nNo KEV overlap found."
    )


print("\n" + "=" * 70)
print("ANALYSIS COMPLETED")
print("=" * 70)