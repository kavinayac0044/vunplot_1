import os
import requests
import json
import time
from datetime import datetime, timedelta, timezone


# ============================================================
# Configuration
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

OUTPUT_PATH = os.path.join(
    BASE_DIR,
    "data",
    "raw",
    "nvd_recent_cves.json"
)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

RESULTS_PER_PAGE = 2000

END_DATE = datetime.now(timezone.utc)
START_DATE = END_DATE - timedelta(days=365)


# ============================================================
# Download one date range
# ============================================================

def download_range(start_date, end_date):

    start_str = start_date.strftime(
        "%Y-%m-%dT%H:%M:%S.000"
    )

    end_str = end_date.strftime(
        "%Y-%m-%dT%H:%M:%S.999"
    )

    records = []
    start_index = 0

    while True:

        params = {
            "pubStartDate": start_str,
            "pubEndDate": end_str,
            "startIndex": start_index,
            "resultsPerPage": RESULTS_PER_PAGE
        }

        print(
            f"Requesting {start_str} -> {end_str}"
        )

        response = requests.get(
            NVD_API,
            params=params,
            timeout=60
        )

        print(
            f"HTTP status: {response.status_code}"
        )

        response.raise_for_status()

        data = response.json()

        vulnerabilities = data.get(
            "vulnerabilities",
            []
        )

        total_results = data.get(
            "totalResults",
            0
        )

        records.extend(
            vulnerabilities
        )

        print(
            f"Received: {len(vulnerabilities)} "
            f"| Total in range: {total_results}"
        )

        if not vulnerabilities:
            break

        start_index += len(vulnerabilities)

        if start_index >= total_results:
            break

        time.sleep(1)

    return records


# ============================================================
# Main
# ============================================================

print("=" * 70)
print("VulnPilot-X - Recent NVD Dataset")
print("=" * 70)

print(
    f"\nOverall start: {START_DATE.isoformat()}"
)

print(
    f"Overall end  : {END_DATE.isoformat()}"
)


all_vulnerabilities = []

current_start = START_DATE

# 100-day chunks (below NVD's 120-day limit)
CHUNK_DAYS = 100

while current_start < END_DATE:

    current_end = min(
        current_start + timedelta(days=CHUNK_DAYS),
        END_DATE
    )

    print("\n" + "-" * 70)
    print(
        f"DATE CHUNK: "
        f"{current_start.date()} -> {current_end.date()}"
    )
    print("-" * 70)

    chunk_records = download_range(
        current_start,
        current_end
    )

    all_vulnerabilities.extend(
        chunk_records
    )

    print(
        f"Chunk records: {len(chunk_records)}"
    )

    current_start = current_end

    time.sleep(1)


# ============================================================
# Remove duplicate CVEs
# ============================================================

unique = {}

for item in all_vulnerabilities:

    cve = item.get(
        "cve",
        {}
    )

    cve_id = cve.get(
        "id"
    )

    if cve_id:
        unique[cve_id] = item


all_vulnerabilities = list(
    unique.values()
)


# ============================================================
# Save
# ============================================================

os.makedirs(
    os.path.dirname(OUTPUT_PATH),
    exist_ok=True
)

output = {
    "resultsPerPage": RESULTS_PER_PAGE,
    "startIndex": 0,
    "totalResults": len(all_vulnerabilities),
    "vulnerabilities": all_vulnerabilities
}

with open(
    OUTPUT_PATH,
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        output,
        f,
        indent=2
    )


# ============================================================
# CVSS availability
# ============================================================

cvss_available = 0

for item in all_vulnerabilities:

    metrics = item.get(
        "cve",
        {}
    ).get(
        "metrics",
        {}
    )

    if any(
        key in metrics
        for key in [
            "cvssMetricV40",
            "cvssMetricV31",
            "cvssMetricV30",
            "cvssMetricV2"
        ]
    ):
        cvss_available += 1


# ============================================================
# Summary
# ============================================================

print("\n" + "=" * 70)
print("DOWNLOAD COMPLETED")
print("=" * 70)

print(
    f"\nUnique recent CVEs : "
    f"{len(all_vulnerabilities)}"
)

print(
    f"CVSS available     : "
    f"{cvss_available}"
)

print(
    f"CVSS unavailable   : "
    f"{len(all_vulnerabilities) - cvss_available}"
)

print(
    f"\nSaved to:\n{OUTPUT_PATH}"
)