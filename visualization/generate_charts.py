import os
import pandas as pd
import matplotlib.pyplot as plt


# ============================================================
# Configuration
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

DATA_PATH = os.path.join(
    BASE_DIR,
    "data",
    "processed",
    "real_ranking_comparison.csv"
)

OUTPUT_DIR = os.path.join(
    BASE_DIR,
    "visualization",
    "outputs"
)

os.makedirs(OUTPUT_DIR, exist_ok=True)


# ============================================================
# Load Data
# ============================================================

df = pd.read_csv(DATA_PATH)

print("\n==============================================")
print("VulnPilot-X - Visualization")
print("==============================================")

print(f"\nRecords loaded: {len(df)}")


# ============================================================
# Chart 1 - CVSS Score Distribution
# ============================================================

plt.figure(figsize=(10, 6))

plt.hist(
    df["cvss_score"],
    bins=20,
    edgecolor="black"
)

plt.title(
    "CVSS Score Distribution - Real NVD Vulnerabilities"
)

plt.xlabel("CVSS Score")
plt.ylabel("Number of Vulnerabilities")

plt.tight_layout()

path = os.path.join(
    OUTPUT_DIR,
    "cvss_distribution.png"
)

plt.savefig(path, dpi=300)
plt.close()

print(f"Created: {path}")


# ============================================================
# Chart 2 - CVSS Rank vs Contextual Rank
# ============================================================

plt.figure(figsize=(10, 8))

plt.scatter(
    df["cvss_rank"],
    df["final_priority_rank"],
    alpha=0.5
)

plt.title(
    "CVSS Rank vs VulnPilot-X Contextual Rank"
)

plt.xlabel("CVSS Baseline Rank")
plt.ylabel("VulnPilot-X Priority Rank")

plt.tight_layout()

path = os.path.join(
    OUTPUT_DIR,
    "rank_comparison.png"
)

plt.savefig(path, dpi=300)
plt.close()

print(f"Created: {path}")


# ============================================================
# Chart 3 - Rank Change Distribution
# ============================================================

plt.figure(figsize=(10, 6))

plt.hist(
    df["rank_change"],
    bins=30,
    edgecolor="black"
)

plt.axvline(
    0,
    linestyle="--",
    linewidth=1.5
)

plt.title(
    "Distribution of Vulnerability Rank Changes"
)

plt.xlabel(
    "Rank Change (CVSS Rank - VulnPilot-X Rank)"
)

plt.ylabel(
    "Number of Vulnerabilities"
)

plt.tight_layout()

path = os.path.join(
    OUTPUT_DIR,
    "rank_change_distribution.png"
)

plt.savefig(path, dpi=300)
plt.close()

print(f"Created: {path}")


# ============================================================
# Chart 4 - Priority Distribution
# ============================================================

priority_counts = (
    df["priority"]
    .value_counts()
    .reindex(
        ["Critical", "High", "Medium", "Low"],
        fill_value=0
    )
)

plt.figure(figsize=(8, 6))

plt.bar(
    priority_counts.index,
    priority_counts.values,
    edgecolor="black"
)

plt.title(
    "VulnPilot-X Priority Distribution"
)

plt.xlabel("Priority")
plt.ylabel("Number of Vulnerabilities")

plt.tight_layout()

path = os.path.join(
    OUTPUT_DIR,
    "priority_distribution.png"
)

plt.savefig(path, dpi=300)
plt.close()

print(f"Created: {path}")


# ============================================================
# Completion
# ============================================================

print("\n==============================================")
print("VISUALIZATION COMPLETED")
print("==============================================")

print("\nCharts generated:")

print("1. cvss_distribution.png")
print("2. rank_comparison.png")
print("3. rank_change_distribution.png")
print("4. priority_distribution.png")

print(
    f"\nOutput directory:\n{OUTPUT_DIR}"
)