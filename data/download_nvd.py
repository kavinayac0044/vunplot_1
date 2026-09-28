import json
import os
import requests

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "raw")
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "nvd_cves.json")

# NVD public CVE API
URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

PARAMS = {
    "resultsPerPage": 2000
}


def download_nvd_data():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("=" * 60)
    print("VulnPilot-X - Real NVD Dataset Download")
    print("=" * 60)
    print("\nConnecting to NVD...")

    response = requests.get(URL, params=PARAMS, timeout=120)
    response.raise_for_status()

    data = response.json()

    vulnerabilities = data.get("vulnerabilities", [])

    print(f"Records received: {len(vulnerabilities)}")

    if not vulnerabilities:
        raise RuntimeError("No vulnerability records were returned.")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)

    print(f"\nReal NVD dataset saved to:")
    print(OUTPUT_FILE)

    print("\nDataset information:")
    print(f"Total results: {data.get('totalResults', 'Unknown')}")
    print(f"Records downloaded: {len(vulnerabilities)}")

    print("\nDownload completed successfully.")


if __name__ == "__main__":
    download_nvd_data()