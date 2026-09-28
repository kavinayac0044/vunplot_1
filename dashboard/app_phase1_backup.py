import os
import pandas as pd
import streamlit as st


# ============================================================
# Page Configuration
# ============================================================

st.set_page_config(
    page_title="VulnPilot-X",
    page_icon="🛡️",
    layout="wide"
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

VIS_DIR = os.path.join(
    BASE_DIR,
    "visualization",
    "outputs"
)


PRIORITY_PATH = os.path.join(
    DATA_DIR,
    "real_priority_results.csv"
)

EXPLANATION_PATH = os.path.join(
    DATA_DIR,
    "real_explanation_results.csv"
)

RANKING_PATH = os.path.join(
    DATA_DIR,
    "real_ranking_comparison.csv"
)

METRICS_PATH = os.path.join(
    DATA_DIR,
    "quantitative_evaluation.csv"
)


# ============================================================
# Load Data
# ============================================================

@st.cache_data
def load_data():

    priority = pd.read_csv(PRIORITY_PATH)

    explanation = pd.read_csv(
        EXPLANATION_PATH
    )

    ranking = pd.read_csv(
        RANKING_PATH
    )

    metrics = pd.read_csv(
        METRICS_PATH
    )

    return priority, explanation, ranking, metrics


try:

    priority_df, explanation_df, ranking_df, metrics_df = (
        load_data()
    )

except Exception as e:

    st.error(
        "Unable to load VulnPilot-X data."
    )

    st.code(str(e))

    st.stop()


# ============================================================
# Header
# ============================================================

st.title("🛡️ VulnPilot-X")

st.subheader(
    "Context-Aware Vulnerability Prioritization System"
)

st.markdown(
    """
    VulnPilot-X analyzes real vulnerability records from the
    National Vulnerability Database (NVD), combines CVSS-based
    severity with contextual risk factors, and produces
    explainable vulnerability priorities.
    """
)

st.divider()


# ============================================================
# Overview Metrics
# ============================================================

total = len(priority_df)

critical = (
    priority_df["priority"] == "Critical"
).sum()

high = (
    priority_df["priority"] == "High"
).sum()

medium = (
    priority_df["priority"] == "Medium"
).sum()

low = (
    priority_df["priority"] == "Low"
).sum()


col1, col2, col3, col4, col5 = st.columns(5)

col1.metric(
    "Total CVEs",
    f"{total:,}"
)

col2.metric(
    "Critical",
    f"{critical:,}"
)

col3.metric(
    "High",
    f"{high:,}"
)

col4.metric(
    "Medium",
    f"{medium:,}"
)

col5.metric(
    "Low",
    f"{low:,}"
)


st.divider()


# ============================================================
# Sidebar Filters
# ============================================================

st.sidebar.header("🔎 Filters")


priority_filter = st.sidebar.multiselect(
    "Priority",
    options=[
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


search_cve = st.sidebar.text_input(
    "Search CVE ID"
)


min_cvss = st.sidebar.slider(
    "Minimum CVSS Score",
    min_value=0.0,
    max_value=10.0,
    value=0.0,
    step=0.1
)


# ============================================================
# Apply Filters
# ============================================================

filtered_df = priority_df[
    priority_df["priority"].isin(
        priority_filter
    )
]

filtered_df = filtered_df[
    filtered_df["cvss_score"] >= min_cvss
]


if search_cve:

    filtered_df = filtered_df[
        filtered_df["cve_id"]
        .str.contains(
            search_cve,
            case=False,
            na=False
        )
    ]


# ============================================================
# Navigation Tabs
# ============================================================

tab1, tab2, tab3, tab4 = st.tabs(
    [
        "📊 Overview",
        "🎯 Prioritized Vulnerabilities",
        "🧠 Explainability",
        "📈 Evaluation"
    ]
)


# ============================================================
# TAB 1 - Overview
# ============================================================

with tab1:

    st.header(
        "Vulnerability Overview"
    )

    col1, col2 = st.columns(2)

    with col1:

        st.subheader(
            "Priority Distribution"
        )

        priority_counts = (
            priority_df["priority"]
            .value_counts()
            .reindex(
                [
                    "Critical",
                    "High",
                    "Medium",
                    "Low"
                ],
                fill_value=0
            )
        )

        st.bar_chart(
            priority_counts
        )

    with col2:

        st.subheader(
            "CVSS Score Distribution"
        )

        cvss_counts = (
            priority_df[
                "cvss_score"
            ]
            .round(1)
            .value_counts()
            .sort_index()
        )

        st.line_chart(
            cvss_counts
        )


    st.subheader(
        "Top Vulnerabilities"
    )

    st.dataframe(
        filtered_df[
            [
                "final_priority_rank",
                "cve_id",
                "cvss_score",
                "contextual_risk_score",
                "priority"
            ]
        ].head(20),
        use_container_width=True,
        hide_index=True
    )


# ============================================================
# TAB 2 - Prioritized Vulnerabilities
# ============================================================

with tab2:

    st.header(
        "Vulnerability Prioritization"
    )

    st.write(
        f"Showing {len(filtered_df):,} vulnerabilities."
    )

    display_columns = [
        "final_priority_rank",
        "cve_id",
        "cvss_score",
        "contextual_risk_score",
        "priority",
        "cvss_version",
        "cwe_id"
    ]

    available_columns = [
        col
        for col in display_columns
        if col in filtered_df.columns
    ]

    st.dataframe(
        filtered_df[
            available_columns
        ],
        use_container_width=True,
        hide_index=True
    )


    st.subheader(
        "Vulnerability Details"
    )

    if len(filtered_df) > 0:

        selected_cve = st.selectbox(
            "Select a CVE",
            filtered_df["cve_id"].tolist()
        )

        selected = filtered_df[
            filtered_df["cve_id"]
            == selected_cve
        ].iloc[0]

        col1, col2, col3 = st.columns(3)

        col1.metric(
            "CVSS Score",
            selected["cvss_score"]
        )

        col2.metric(
            "Contextual Risk",
            selected["contextual_risk_score"]
        )

        col3.metric(
            "Priority",
            selected["priority"]
        )

        st.write(
            "**CVE ID:**",
            selected["cve_id"]
        )

        if "description" in selected:

            st.write(
                "**Description:**"
            )

            st.write(
                selected["description"]
            )

        if "cwe_id" in selected:

            st.write(
                "**CWE:**",
                selected["cwe_id"]
            )


# ============================================================
# TAB 3 - Explainability
# ============================================================

with tab3:

    st.header(
        "🧠 Explainable Prioritization"
    )

    explanation_search = st.text_input(
        "Search for a CVE to view its explanation",
        key="explanation_search"
    )

    explanation_view = explanation_df.copy()

    if explanation_search:

        explanation_view = explanation_view[
            explanation_view["cve_id"]
            .str.contains(
                explanation_search,
                case=False,
                na=False
            )
        ]

    st.dataframe(
        explanation_view[
            [
                "final_priority_rank",
                "cve_id",
                "priority",
                "contextual_risk_score",
                "explanation",
                "recommendation"
            ]
        ].head(50),
        use_container_width=True,
        hide_index=True
    )


# ============================================================
# TAB 4 - Evaluation
# ============================================================

with tab4:

    st.header(
        "📈 Quantitative Evaluation"
    )

    st.markdown(
        """
        The contextual ranking is compared with the CVSS-only
        baseline using rank correlation, rank changes and
        Top-K overlap measures.
        """
    )

    # --------------------------------------------------------
    # Metrics
    # --------------------------------------------------------

    metric_dict = dict(
        zip(
            metrics_df["metric"],
            metrics_df["value"]
        )
    )

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Spearman Correlation",
        metric_dict.get(
            "Spearman rank correlation",
            "N/A"
        )
    )

    col2.metric(
        "Mean Rank Change",
        metric_dict.get(
            "Mean absolute rank change",
            "N/A"
        )
    )

    col3.metric(
        "Changed Rankings",
        metric_dict.get(
            "Percentage of rankings changed",
            "N/A"
        )
    )


    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Top-10 Overlap",
        metric_dict.get(
            "Top-10 overlap",
            "N/A"
        )
    )

    col2.metric(
        "Top-25 Overlap",
        metric_dict.get(
            "Top-25 overlap",
            "N/A"
        )
    )

    col3.metric(
        "Top-50 Overlap",
        metric_dict.get(
            "Top-50 overlap",
            "N/A"
        )
    )


    st.subheader(
        "Quantitative Evaluation Metrics"
    )

    st.dataframe(
        metrics_df,
        use_container_width=True,
        hide_index=True
    )


    # --------------------------------------------------------
    # Ranking Comparison
    # --------------------------------------------------------

    st.subheader(
        "CVSS vs VulnPilot-X Ranking"
    )

    st.scatter_chart(
        ranking_df,
        x="cvss_rank",
        y="final_priority_rank"
    )


# ============================================================
# Footer
# ============================================================

st.divider()

st.caption(
    "VulnPilot-X | Phase-I Prototype | "
    "Real NVD Vulnerability Dataset"
)