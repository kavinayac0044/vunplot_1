import os
import pandas as pd
import streamlit as st


# ============================================================
# VulnPilot-X — Phase-I Research Dashboard
# ============================================================

st.set_page_config(
    page_title="VulnPilot-X | Phase-I",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# ============================================================
# Paths
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

DATA_DIR = os.path.join(
    BASE_DIR,
    "data",
    "processed"
)


# ============================================================
# Data Loading
# ============================================================

@st.cache_data
def load_phase1_data():

    master = pd.read_csv(
        os.path.join(
            DATA_DIR,
            "phase1_master_dataset.csv"
        )
    )

    priority = pd.read_csv(
        os.path.join(
            DATA_DIR,
            "phase1_priority_results.csv"
        )
    )

    explanation = pd.read_csv(
        os.path.join(
            DATA_DIR,
            "phase1_explanation_results.csv"
        )
    )

    final_summary = pd.read_csv(
        os.path.join(
            DATA_DIR,
            "phase1_final_evaluation_summary.csv"
        )
    )

    baseline = pd.read_csv(
        os.path.join(
            DATA_DIR,
            "phase1_final_baseline_evaluation.csv"
        )
    )

    temporal = pd.read_csv(
        os.path.join(
            DATA_DIR,
            "phase1_final_temporal_evaluation.csv"
        )
    )

    topk = pd.read_csv(
        os.path.join(
            DATA_DIR,
            "phase1_final_topk_comparison.csv"
        )
    )

    rank_movement = pd.read_csv(
        os.path.join(
            DATA_DIR,
            "phase1_final_rank_movement.csv"
        )
    )

    priority_distribution = pd.read_csv(
        os.path.join(
            DATA_DIR,
            "phase1_final_priority_distribution.csv"
        )
    )

    context = pd.read_csv(
        os.path.join(
            DATA_DIR,
            "phase1_final_context_validation.csv"
        )
    )

    explainability = pd.read_csv(
        os.path.join(
            DATA_DIR,
            "phase1_final_explainability_validation.csv"
        )
    )

    sensitivity = pd.read_csv(
        os.path.join(
            DATA_DIR,
            "phase1_context_sensitivity.csv"
        )
    )

    return (
        master,
        priority,
        explanation,
        final_summary,
        baseline,
        temporal,
        topk,
        rank_movement,
        priority_distribution,
        context,
        explainability,
        sensitivity
    )


# ============================================================
# Load
# ============================================================

try:

    (
        master_df,
        priority_df,
        explanation_df,
        summary_df,
        baseline_df,
        temporal_df,
        topk_df,
        rank_movement_df,
        priority_distribution_df,
        context_df,
        explainability_df,
        sensitivity_df
    ) = load_phase1_data()

except Exception as e:

    st.error(
        "Unable to load Phase-I VulnPilot-X data."
    )

    st.code(str(e))

    st.stop()


# ============================================================
# Helper Functions
# ============================================================

def get_summary_value(metric):

    result = summary_df[
        summary_df["metric"] == metric
    ]

    if len(result) == 0:
        return 0

    return result.iloc[0]["value"]


def priority_counts():

    order = [
        "Critical",
        "High",
        "Medium",
        "Low"
    ]

    return (
        priority_df["priority"]
        .value_counts()
        .reindex(
            order,
            fill_value=0
        )
    )


# ============================================================
# Header
# ============================================================

st.title("🛡️ VulnPilot-X")

st.subheader(
    "Context-Aware Vulnerability Prioritization"
)

st.markdown(
    """
**Phase-I: Vulnerability Intelligence & Prioritization**

VulnPilot-X integrates CVSS severity, EPSS exploitation
likelihood, CISA KEV exploitation evidence, and controlled
asset criticality to generate explainable vulnerability
priorities.
"""
)

st.divider()


# ============================================================
# Sidebar
# ============================================================

st.sidebar.title("🛡️ VulnPilot-X")

st.sidebar.caption(
    "Phase-I Research Dashboard"
)

st.sidebar.divider()

page = st.sidebar.radio(
    "Navigation",
    [
        "📊 Overview",
        "🎯 Priority Queue",
        "🔍 CVE Explorer",
        "🧠 Explainability",
        "📈 Evaluation",
        "🧪 Context Sensitivity"
    ]
)

st.sidebar.divider()

st.sidebar.caption(
    "Dataset: 3,000 recent NVD vulnerabilities"
)

st.sidebar.caption(
    "EPSS coverage: 99.6%"
)


# ============================================================
# Global Metrics
# ============================================================

total_cves = int(
    get_summary_value("Total CVEs")
)

epss_available = int(
    get_summary_value("EPSS available")
)

kev_count = int(
    get_summary_value("KEV cases")
)

critical_count = int(
    (
        priority_df["priority"] == "Critical"
    ).sum()
)

high_count = int(
    (
        priority_df["priority"] == "High"
    ).sum()
)


# ============================================================
# PAGE 1 — OVERVIEW
# ============================================================

if page == "📊 Overview":

    st.header(
        "📊 Phase-I Vulnerability Intelligence Overview"
    )

    # --------------------------------------------------------
    # KPI Cards
    # --------------------------------------------------------

    col1, col2, col3, col4, col5 = st.columns(5)

    col1.metric(
        "Total CVEs",
        f"{total_cves:,}"
    )

    col2.metric(
        "Critical",
        f"{critical_count:,}"
    )

    col3.metric(
        "High",
        f"{high_count:,}"
    )

    col4.metric(
        "KEV Cases",
        f"{kev_count:,}"
    )

    col5.metric(
        "EPSS Available",
        f"{epss_available:,}"
    )

    st.divider()

    # --------------------------------------------------------
    # Priority Distribution
    # --------------------------------------------------------

    col1, col2 = st.columns(2)

    with col1:

        st.subheader(
            "Priority Distribution"
        )

        counts = priority_counts()

        st.bar_chart(
            counts
        )

    with col2:

        st.subheader(
            "CVSS Distribution"
        )

        cvss_distribution = (
            priority_df[
                "cvss_score"
            ]
            .round(1)
            .value_counts()
            .sort_index()
        )

        st.line_chart(
            cvss_distribution
        )

    st.divider()

    # --------------------------------------------------------
    # Top Priority Vulnerabilities
    # --------------------------------------------------------

    st.subheader(
        "🚨 Top Priority Vulnerabilities"
    )

    top_columns = [
        "final_priority_rank",
        "cve_id",
        "cvss_score",
        "epss_score",
        "kev_status",
        "asset_type",
        "contextual_risk_score",
        "priority"
    ]

    available = [
        col for col in top_columns
        if col in priority_df.columns
    ]

    st.dataframe(
        priority_df[
            available
        ].head(15),
        use_container_width=True,
        hide_index=True
    )

    st.info(
        "Asset context in Phase-I is a controlled experimental "
        "scenario rather than an observed enterprise asset inventory."
    )


# ============================================================
# PAGE 2 — PRIORITY QUEUE
# ============================================================

elif page == "🎯 Priority Queue":

    st.header(
        "🎯 VulnPilot-X Priority Queue"
    )

    st.markdown(
        """
Use the filters below to investigate vulnerabilities
according to contextual priority.
"""
    )

    # --------------------------------------------------------
    # Filters
    # --------------------------------------------------------

    col1, col2, col3, col4 = st.columns(4)

    with col1:

        selected_priorities = st.multiselect(
            "Priority",
            [
                "Critical",
                "High",
                "Medium",
                "Low"
            ],
            default=[
                "Critical",
                "High",
                "Medium",
                "Low"
            ]
        )

    with col2:

        min_cvss = st.slider(
            "Minimum CVSS",
            0.0,
            10.0,
            0.0,
            0.1
        )

    with col3:

        kev_filter = st.selectbox(
            "KEV Status",
            [
                "All",
                "KEV",
                "Non-KEV"
            ]
        )

    with col4:

        search = st.text_input(
            "Search CVE"
        )

    filtered = priority_df[
        priority_df["priority"].isin(
            selected_priorities
        )
    ]

    filtered = filtered[
        filtered["cvss_score"] >= min_cvss
    ]

    if kev_filter == "KEV":

        filtered = filtered[
            filtered["kev_status"] == 1
        ]

    elif kev_filter == "Non-KEV":

        filtered = filtered[
            filtered["kev_status"] == 0
        ]

    if search:

        filtered = filtered[
            filtered["cve_id"]
            .str.contains(
                search,
                case=False,
                na=False
            )
        ]

    st.write(
        f"Showing **{len(filtered):,}** vulnerabilities."
    )

    display_columns = [
        "final_priority_rank",
        "cve_id",
        "cvss_score",
        "epss_score",
        "kev_status",
        "asset_type",
        "asset_criticality",
        "contextual_risk_score",
        "priority",
        "rank_change_vs_cvss",
        "rank_movement",
        "priority_action"
    ]

    available = [
        col for col in display_columns
        if col in filtered.columns
    ]

    st.dataframe(
        filtered[
            available
        ],
        use_container_width=True,
        hide_index=True,
        height=550
    )


# ============================================================
# PAGE 3 — CVE EXPLORER
# ============================================================

elif page == "🔍 CVE Explorer":

    st.header(
        "🔍 Vulnerability Explorer"
    )

    cve_list = (
        priority_df
        .sort_values(
            "final_priority_rank"
        )["cve_id"]
        .tolist()
    )

    selected_cve = st.selectbox(
        "Select a vulnerability",
        cve_list
    )

    selected = priority_df[
        priority_df["cve_id"] == selected_cve
    ].iloc[0]

    st.divider()

    # --------------------------------------------------------
    # Main Metrics
    # --------------------------------------------------------

    col1, col2, col3, col4, col5 = st.columns(5)

    col1.metric(
        "VulnPilot-X Rank",
        int(selected["final_priority_rank"])
    )

    col2.metric(
        "CVSS",
        f"{selected['cvss_score']:.1f}"
    )

    epss_value = selected["epss_score"]

    if pd.notna(epss_value):

        epss_display = f"{epss_value:.5f}"

    else:

        epss_display = "Unavailable"

    col3.metric(
        "EPSS",
        epss_display
    )

    col4.metric(
        "Contextual Risk",
        f"{selected['contextual_risk_score']:.2f}"
    )

    col5.metric(
        "Priority",
        selected["priority"]
    )

    st.divider()

    # --------------------------------------------------------
    # Evidence
    # --------------------------------------------------------

    st.subheader(
        "Risk Evidence"
    )

    evidence_col1, evidence_col2 = st.columns(2)

    with evidence_col1:

        st.write(
            f"**CVE:** {selected['cve_id']}"
        )

        st.write(
            f"**CVSS Version:** "
            f"{selected['cvss_version']}"
        )

        st.write(
            f"**KEV Status:** "
            f"{'Known Exploited' if selected['kev_status'] == 1 else 'Not listed'}"
        )

        st.write(
            f"**Asset Type:** "
            f"{selected['asset_type']}"
        )

    with evidence_col2:

        st.write(
            f"**Asset Criticality:** "
            f"{selected['asset_criticality']:.2f}"
        )

        st.write(
            f"**CVSS Rank:** "
            f"{int(selected['cvss_rank'])}"
        )

        st.write(
            f"**Rank Movement:** "
            f"{selected['rank_movement']}"
        )

        st.write(
            f"**Priority Action:** "
            f"{selected['priority_action']}"
        )

    if "description" in selected:

        st.subheader(
            "Description"
        )

        st.write(
            selected["description"]
        )


# ============================================================
# PAGE 4 — EXPLAINABILITY
# ============================================================

elif page == "🧠 Explainability":

    st.header(
        "🧠 Explainable Prioritization"
    )

    st.markdown(
        """
VulnPilot-X provides an evidence-based explanation of why
a vulnerability received its contextual priority.
"""
    )

    selected_cve = st.selectbox(
        "Select CVE",
        explanation_df[
            "cve_id"
        ].tolist(),
        key="explanation_cve"
    )

    row = explanation_df[
        explanation_df["cve_id"] == selected_cve
    ].iloc[0]

    # --------------------------------------------------------
    # Score
    # --------------------------------------------------------

    st.subheader(
        "Contextual Risk Score"
    )

    st.metric(
        "Risk Score",
        f"{row['contextual_risk_score']:.2f}"
    )

    st.write(
        f"**Priority:** {row['priority']}"
    )

    st.write(
        f"**Evidence Status:** "
        f"{row['evidence_status']}"
    )

    st.divider()

    # --------------------------------------------------------
    # Contributions
    # --------------------------------------------------------

    st.subheader(
        "Score Contributions"
    )

    contribution_data = pd.DataFrame(
        {
            "Evidence": [
                "CVSS",
                "EPSS",
                "KEV",
                "Asset Criticality"
            ],
            "Contribution": [
                row["cvss_contribution"],
                row["epss_contribution"],
                row["kev_contribution"],
                row["asset_contribution"]
            ]
        }
    )

    st.bar_chart(
        contribution_data.set_index(
            "Evidence"
        )
    )

    st.divider()

    # --------------------------------------------------------
    # Explanation
    # --------------------------------------------------------

    st.subheader(
        "Why was this vulnerability prioritized?"
    )

    st.info(
        row["explanation"]
    )

    st.subheader(
        "Recommended Action"
    )

    st.success(
        row["recommendation"]
    )

    st.subheader(
        "Risk Evidence"
    )

    st.write(
        row["risk_evidence"]
    )


# ============================================================
# PAGE 5 — EVALUATION
# ============================================================

elif page == "📈 Evaluation":

    st.header(
        "📈 Phase-I Quantitative Evaluation"
    )

    st.markdown(
        """
This section separates the independent evaluation from the
temporal future-holdout evaluation.
"""
    )

    # --------------------------------------------------------
    # Dataset
    # --------------------------------------------------------

    st.subheader(
        "Dataset Summary"
    )

    st.dataframe(
        summary_df,
        use_container_width=True,
        hide_index=True
    )

    st.divider()

    # --------------------------------------------------------
    # Independent Evaluation
    # --------------------------------------------------------

    st.subheader(
        "Independent Top-K Evaluation"
    )

    st.dataframe(
        baseline_df[
            [
                "strategy",
                "precision_at_100",
                "recall_at_100",
                "f1_at_100",
                "ndcg_at_100"
            ]
        ],
        use_container_width=True,
        hide_index=True
    )

    st.caption(
        "KEV is used as the evaluation target in this analysis. "
        "Results should be interpreted descriptively because KEV "
        "is also used by some strategies as an input feature."
    )

    st.divider()

    # --------------------------------------------------------
    # Temporal Holdout
    # --------------------------------------------------------

    st.subheader(
        "Temporal Future-Holdout Evaluation"
    )

    st.dataframe(
        temporal_df[
            [
                "strategy",
                "holdout_records",
                "holdout_kev_count",
                "precision_at_100",
                "recall_at_100",
                "f1_at_100",
                "ndcg_at_100"
            ]
        ],
        use_container_width=True,
        hide_index=True
    )

    st.divider()

    # --------------------------------------------------------
    # Rank Movement
    # --------------------------------------------------------

    col1, col2 = st.columns(2)

    with col1:

        st.subheader(
            "Rank Movement"
        )

        st.dataframe(
            rank_movement_df,
            use_container_width=True,
            hide_index=True
        )

    with col2:

        st.subheader(
            "Priority Distribution"
        )

        st.dataframe(
            priority_distribution_df,
            use_container_width=True,
            hide_index=True
        )

    st.divider()

    # --------------------------------------------------------
    # Top-K
    # --------------------------------------------------------

    st.subheader(
        "Temporal Top-K Comparison"
    )

    st.dataframe(
        topk_df,
        use_container_width=True,
        hide_index=True
    )

    st.divider()

    # --------------------------------------------------------
    # Explainability Validation
    # --------------------------------------------------------

    st.subheader(
        "Explainability Validation"
    )

    st.dataframe(
        explainability_df,
        use_container_width=True,
        hide_index=True
    )


# ============================================================
# PAGE 6 — CONTEXT SENSITIVITY
# ============================================================

elif page == "🧪 Context Sensitivity":

    st.header(
        "🧪 Controlled Asset-Context Sensitivity"
    )

    st.markdown(
        """
The same vulnerability is evaluated under different controlled
asset criticality contexts to verify whether contextual risk
changes consistently with asset importance.
"""
    )

    # --------------------------------------------------------
    # Validation Results
    # --------------------------------------------------------

    st.subheader(
        "Validation Results"
    )

    st.dataframe(
        context_df,
        use_container_width=True,
        hide_index=True
    )

    st.divider()

    # --------------------------------------------------------
    # Sensitivity Data
    # --------------------------------------------------------

    st.subheader(
        "Risk Across Asset Contexts"
    )

    for cve_id in sensitivity_df[
        "cve_id"
    ].unique():

        st.markdown(
            f"### {cve_id}"
        )

        cve_data = sensitivity_df[
            sensitivity_df["cve_id"] == cve_id
        ].copy()

        chart_data = cve_data[
            [
                "asset_type",
                "contextual_risk_score"
            ]
        ].set_index(
            "asset_type"
        )

        st.line_chart(
            chart_data
        )

    st.info(
        "Asset assignments are controlled experimental contexts "
        "and should not be interpreted as real enterprise asset "
        "inventory observations."
    )


# ============================================================
# Footer
# ============================================================

st.divider()

st.caption(
    "VulnPilot-X | Phase-I | "
    "Multi-factor Context-Aware Vulnerability Prioritization"
)

st.caption(
    "Research prototype — asset context is controlled/synthetic."
)