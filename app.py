import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go

import urllib.request
import urllib.parse
import zipfile
import io
import re
import html
import ipaddress

from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)

# ============================================================
# SENTINEL AI | APPLICATION CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="SENTINEL AI | Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

DATA_URL = (
    "https://archive.ics.uci.edu/static/public/228/"
    "sms+spam+collection.zip"
)

# ============================================================
# PREMIUM CYBERSECURITY DESIGN
# ============================================================

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

:root {
    --bg: #070b14;
    --panel: #101827;
    --border: #25344b;
    --cyan: #21d4fd;
    --blue: #5278ff;
    --red: #ff5575;
    --text: #edf3fc;
    --muted: #8b9bb2;
}

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

.stApp {
    background:
        radial-gradient(circle at 80% 0%, rgba(33,212,253,.09), transparent 28%),
        radial-gradient(circle at 5% 90%, rgba(82,120,255,.08), transparent 28%),
        var(--bg);
    color: var(--text);
}

.block-container {
    max-width: 1500px;
    padding-top: 2rem;
    padding-bottom: 3rem;
}

[data-testid="stSidebar"] {
    background: #0a101c;
    border-right: 1px solid var(--border);
}

[data-testid="stSidebar"] * {
    color: var(--text);
}

h1, h2, h3, h4 {
    color: #f4f7ff !important;
    letter-spacing: -.4px;
}

p, label {
    color: #c4cfdf;
}

.vx-brand {
    display: flex;
    align-items: center;
    gap: 13px;
    padding: 8px 0 22px 0;
}

.vx-logo {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 46px;
    height: 46px;
    border-radius: 14px;
    background: linear-gradient(135deg, #21d4fd, #5278ff);
    color: #07111f;
    font-size: 23px;
    font-weight: 900;
    box-shadow: 0 0 25px rgba(33,212,253,.2);
}

.vx-brand-name {
    font-size: 22px;
    font-weight: 800;
    letter-spacing: 2px;
    color: white;
}

.vx-brand-sub {
    color: #8293aa;
    font-size: 9px;
    letter-spacing: 1.7px;
    margin-top: 3px;
}

.vx-eyebrow {
    color: var(--cyan);
    font-size: 11px;
    font-weight: 800;
    letter-spacing: 2px;
    text-transform: uppercase;
}

.vx-hero {
    padding: 28px;
    border-radius: 20px;
    border: 1px solid #2a3b55;
    background: linear-gradient(120deg, #142238, #0d1524 75%);
    margin: 18px 0 22px 0;
}

.vx-hero-title {
    color: white;
    font-size: clamp(27px, 4vw, 39px);
    font-weight: 800;
    line-height: 1.2;
    margin: 10px 0;
}

.vx-hero-copy {
    color: #a3b3c9;
    font-size: 14px;
    max-width: 760px;
    line-height: 1.7;
}

.vx-pill {
    display: inline-block;
    padding: 6px 11px;
    border-radius: 30px;
    border: 1px solid rgba(33,212,253,.35);
    background: rgba(33,212,253,.08);
    color: #56ddff;
    font-size: 10px;
    font-weight: 800;
    letter-spacing: 1px;
}

.vx-panel {
    background: linear-gradient(145deg, #121d2d, #0d1522);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 20px;
}

.vx-stat {
    background: linear-gradient(145deg, #121e30, #0c1421);
    border: 1px solid #293b54;
    border-radius: 15px;
    padding: 18px;
    min-height: 112px;
}

.vx-stat-label {
    font-size: 11px;
    color: #91a2b9;
    letter-spacing: 1px;
    text-transform: uppercase;
}

.vx-stat-value {
    color: #f4f7ff;
    font-size: 28px;
    font-weight: 800;
    margin-top: 8px;
}

.vx-stat-note {
    color: var(--cyan);
    font-size: 11px;
    margin-top: 3px;
}

.vx-section {
    font-size: 19px;
    font-weight: 750;
    margin: 26px 0 12px 0;
    color: #f4f7ff;
}

.vx-muted {
    color: var(--muted);
    font-size: 13px;
}

.vx-danger {
    color: #ff7890;
    font-weight: 750;
}

.vx-safe {
    color: #47e3b0;
    font-weight: 750;
}

.vx-chip {
    display: inline-block;
    background: rgba(255,85,117,.11);
    color: #ff8298;
    border: 1px solid rgba(255,85,117,.3);
    padding: 5px 9px;
    border-radius: 7px;
    font-size: 12px;
    margin: 3px;
}

.stButton > button {
    background: linear-gradient(90deg, #17c9ed, #5278ff);
    color: #07111f;
    border: none;
    border-radius: 10px;
    min-height: 44px;
    font-weight: 800;
}

.stButton > button:hover {
    color: white;
    border: 1px solid #21d4fd;
    box-shadow: 0 0 20px rgba(33,212,253,.15);
}

.stDownloadButton > button {
    border: 1px solid #2b4662;
    border-radius: 9px;
    background: #142337;
    color: #dcecff;
}

[data-testid="stFileUploader"] {
    border: 1px dashed #344b68;
    background: #101a29;
    border-radius: 14px;
    padding: 12px;
}

[data-testid="stMetric"] {
    background: #111c2b;
    border: 1px solid #293b54;
    border-radius: 12px;
    padding: 13px;
}

[data-testid="stMetricValue"] {
    color: #21d4fd !important;
}

hr {
    border-color: #25344b;
}

footer {
    visibility: hidden;
}

#MainMenu {
    visibility: hidden;
}
</style>
""", unsafe_allow_html=True)


# ============================================================
# DATASET DOWNLOAD AND MODEL TRAINING
# ============================================================

@st.cache_data(show_spinner=False)
def load_dataset():
    """Download and load the public UCI SMS Spam Collection."""
    request = urllib.request.Request(
        DATA_URL,
        headers={"User-Agent": "SENTINEL-AI/1.0"}
    )

    with urllib.request.urlopen(request, timeout=40) as response:
        archive_bytes = response.read()

    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        dataset_file = archive.read("SMSSpamCollection")

    data = pd.read_csv(
        io.BytesIO(dataset_file),
        sep="\t",
        header=None,
        names=["label", "message"],
        encoding="utf-8",
        quoting=3,
    )

    data = data.dropna()
    data["label"] = data["label"].str.strip().str.lower()
    data["message"] = data["message"].astype(str).str.strip()

    data = data[
        data["label"].isin(["ham", "spam"])
        & (data["message"].str.len() > 0)
    ]

    return data.drop_duplicates(
        subset="message"
    ).reset_index(drop=True)


@st.cache_resource(show_spinner=False)
def train_model():
    """Train a TF-IDF + Logistic Regression spam classifier."""

    data = load_dataset()

    X_train, X_test, y_train, y_test = train_test_split(
        data["message"],
        data["label"],
        test_size=0.20,
        random_state=42,
        stratify=data["label"],
    )

    model = Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                lowercase=True,
                stop_words="english",
                ngram_range=(1, 2),
                max_features=30000,
                sublinear_tf=True,
            ),
        ),
        (
            "classifier",
            LogisticRegression(
                max_iter=1000,
                class_weight="balanced",
                random_state=42,
            ),
        ),
    ])

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    metrics = {
        "accuracy": accuracy_score(y_test, predictions),
        "precision": precision_score(
            y_test, predictions, pos_label="spam", zero_division=0
        ),
        "recall": recall_score(
            y_test, predictions, pos_label="spam", zero_division=0
        ),
        "f1": f1_score(
            y_test, predictions, pos_label="spam", zero_division=0
        ),
        "confusion": confusion_matrix(
            y_test, predictions, labels=["ham", "spam"]
        ),
        "test_size": len(y_test),
        "train_size": len(X_train),
    }

    return model, metrics, len(data)


# ============================================================
# MESSAGE ANALYSIS
# ============================================================

def analyze_message(model, message, threshold):
    """Return the predicted class, spam score and model signals."""

    probabilities = model.predict_proba([message])[0]
    classes = list(model.classes_)
    spam_index = classes.index("spam")

    spam_score = float(probabilities[spam_index])
    prediction = "spam" if spam_score >= threshold else "ham"

    # Extract positive learned feature contributions.
    vectorizer = model.named_steps["tfidf"]
    classifier = model.named_steps["classifier"]

    vector = vectorizer.transform([message])
    contributions = vector.multiply(classifier.coef_[0]).tocoo()
    feature_names = vectorizer.get_feature_names_out()

    signals = []

    weighted_features = sorted(
        zip(contributions.col, contributions.data),
        key=lambda item: item[1],
        reverse=True,
    )

    for feature_index, contribution in weighted_features:
        if contribution <= 0:
            continue

        feature = str(feature_names[feature_index])

        if feature not in signals:
            signals.append(feature)

        if len(signals) == 6:
            break

    return {
        "prediction": prediction,
        "spam_score": spam_score,
        "signals": signals,
        "ham_score": float(probabilities[classes.index("ham")]),
    }


# ============================================================
# URL RISK INSPECTOR
# ============================================================

def inspect_url(raw_url):
    """
    Heuristic URL inspection.
    This does not visit the URL or verify whether a site is malicious.
    """

    raw_url = raw_url.strip()
    if not raw_url:
        return None

    candidate = raw_url
    if not re.match(r"^https?://", candidate, flags=re.I):
        candidate = "https://" + candidate

    parsed = urllib.parse.urlparse(candidate)
    host = parsed.hostname or ""
    findings = []
    score = 0

    if not host:
        return {
            "score": 0,
            "findings": ["The URL could not be parsed."],
            "host": "Unknown",
        }

    if raw_url.lower().startswith("http://"):
        score += 15
        findings.append("Uses unencrypted HTTP rather than HTTPS.")

    try:
        ipaddress.ip_address(host)
        score += 35
        findings.append("Uses a raw IP address instead of a normal domain.")
    except ValueError:
        pass

    if "xn--" in host:
        score += 25
        findings.append("Contains a punycode domain label.")

    shorteners = {
        "bit.ly", "tinyurl.com", "t.co", "is.gd",
        "cutt.ly", "shorturl.at", "rebrand.ly",
    }

    if host.lower() in shorteners:
        score += 20
        findings.append("Uses a URL shortening service.")

    if "@" in parsed.netloc:
        score += 25
        findings.append("Contains an @ symbol in the URL authority.")

    if host.count(".") >= 3:
        score += 10
        findings.append("Contains several subdomain levels.")

    suspicious_terms = [
        "login", "verify", "account", "secure",
        "update", "wallet", "password", "payment",
        "claim", "reward", "free", "bank",
    ]

    matched_terms = [
        term for term in suspicious_terms
        if term in (host + parsed.path + parsed.query).lower()
    ]

    if matched_terms:
        score += min(25, len(matched_terms) * 8)
        findings.append(
            "Contains sensitive or urgency-related terms: "
            + ", ".join(matched_terms[:5])
        )

    if len(raw_url) > 100:
        score += 10
        findings.append("Unusually long URL.")

    score = min(100, score)

    if not findings:
        findings.append(
            "No basic structural warning signs were found. "
            "This does not prove the site is safe."
        )

    return {
        "score": score,
        "findings": findings,
        "host": host,
    }


# ============================================================
# REUSABLE DISPLAY HELPERS
# ============================================================

def show_stat(label, value, note):
    st.markdown(
        f"""
        <div class="vx-stat">
            <div class="vx-stat-label">{label}</div>
            <div class="vx-stat-value">{value}</div>
            <div class="vx-stat-note">{note}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def risk_band(score):
    if score >= 65:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


# ============================================================
# TRAIN MODEL
# ============================================================

with st.spinner(
    "Initializing SENTINEL AI and training the machine-learning model..."
):
    try:
        model, metrics, dataset_size = train_model()
        dataset = load_dataset()

    except Exception as error:
        st.error(
            "SENTINEL AI could not load its training dataset or train "
            "the model. Check your internet connection and try again."
        )
        st.code(str(error))
        st.stop()


if "scan_count" not in st.session_state:
    st.session_state.scan_count = 0


# ============================================================
# SIDEBAR NAVIGATION
# ============================================================

with st.sidebar:

    st.markdown("""
    <div class="vx-brand">
        <div class="vx-logo">S</div>
        <div>
            <div class="vx-brand-name">SENTINEL AI</div>
            <div class="vx-brand-sub">THREAT INTELLIGENCE PLATFORM</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    st.markdown(
        '<div class="vx-eyebrow">INTELLIGENCE CENTER</div>',
        unsafe_allow_html=True,
    )

    page = st.radio(
        "Navigation",
        [
            "Overview",
            "Message Scanner",
            "URL Inspector",
            "Batch Analysis",
            "Model Lab",
            "About",
        ],
        label_visibility="collapsed",
    )

    st.markdown("---")

    st.markdown(
        '<div class="vx-eyebrow">SYSTEM STATUS</div>',
        unsafe_allow_html=True,
    )

    st.markdown("""
    <p style="font-size:13px;">🟢 ML Engine <span style="float:right;color:#47e3b0;">READY</span></p>
    <p style="font-size:13px;">🟢 NLP Pipeline <span style="float:right;color:#47e3b0;">ACTIVE</span></p>
    <p style="font-size:13px;">🟢 Dataset <span style="float:right;color:#47e3b0;">LOADED</span></p>
    """, unsafe_allow_html=True)

    st.markdown("---")

    threshold = st.slider(
        "Spam decision threshold",
        min_value=0.20,
        max_value=0.90,
        value=0.50,
        step=0.05,
        help=(
            "Lower thresholds flag more messages. "
            "This changes the classification rule, not the trained model."
        ),
    )

    st.caption("SENTINEL AI · BUILD 1.0")
    st.caption("Defensive security research prototype")


# ============================================================
# TOP HEADER
# ============================================================

st.markdown(
    '<div class="vx-eyebrow">ARTIFICIAL INTELLIGENCE / SECURITY OPERATIONS</div>',
    unsafe_allow_html=True,
)

st.title("Threat Intelligence Command Center")

st.markdown(
    """
    <div class="vx-muted">
        Detect suspicious messages · Inspect URL indicators ·
        Investigate machine-learning signals
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown("")


# ============================================================
# OVERVIEW PAGE
# ============================================================

if page == "Overview":

    st.markdown("""
    <div class="vx-hero">
        <div class="vx-eyebrow">SENTINEL CORE ENGINE · OPERATIONAL</div>
        <div class="vx-hero-title">
            Intelligence before interaction.
        </div>
        <div class="vx-hero-copy">
            An explainable machine-learning workspace for identifying
            potentially fraudulent SMS messages and inspecting suspicious
            web addresses. Analyse signals, investigate patterns and
            understand model decisions.
        </div>
        <br>
        <span class="vx-pill">● ML ENGINE TRAINED</span>
        &nbsp;
        <span class="vx-pill">● NLP PIPELINE ACTIVE</span>
        &nbsp;
        <span class="vx-pill">● DATASET LOADED</span>
    </div>
    """, unsafe_allow_html=True)

    spam_count = int((dataset["label"] == "spam").sum())
    ham_count = int((dataset["label"] == "ham").sum())

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        show_stat("TRAINING RECORDS", f"{dataset_size:,}", "UCI SMS dataset")

    with col2:
        show_stat("SPAM EXAMPLES", f"{spam_count:,}", "Labelled spam")

    with col3:
        show_stat("LEGITIMATE EXAMPLES", f"{ham_count:,}", "Labelled ham")

    with col4:
        show_stat("TEST F1 SCORE", f"{metrics['f1']:.1%}", "Held-out test split")

    st.markdown(
        '<div class="vx-section">◈ Intelligence Overview</div>',
        unsafe_allow_html=True,
    )

    left, right = st.columns([1.15, 1])

    with left:
        st.markdown("#### Training Dataset Composition")

        composition = pd.DataFrame({
            "Class": ["Legitimate", "Spam"],
            "Messages": [ham_count, spam_count],
        })

        fig = px.pie(
            composition,
            names="Class",
            values="Messages",
            hole=0.68,
            color="Class",
            color_discrete_map={
                "Legitimate": "#21d4fd",
                "Spam": "#ff5575",
            },
        )

        fig.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            margin=dict(l=10, r=10, t=20, b=10),
            legend=dict(orientation="h", y=-0.1),
        )

        st.plotly_chart(fig, use_container_width=True)

    with right:
        st.markdown("#### Model Performance")

        performance = pd.DataFrame({
            "Metric": ["Accuracy", "Precision", "Recall", "F1 Score"],
            "Score": [
                metrics["accuracy"],
                metrics["precision"],
                metrics["recall"],
                metrics["f1"],
            ],
        })

        fig = px.bar(
            performance,
            x="Metric",
            y="Score",
            color="Score",
            range_y=[0, 1],
        )

        fig.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            yaxis_title="Score",
            xaxis_title="",
            showlegend=False,
            margin=dict(l=10, r=10, t=20, b=10),
        )

        st.plotly_chart(fig, use_container_width=True)

    st.markdown(
        '<div class="vx-section">◈ Quick Investigation</div>',
        unsafe_allow_html=True,
    )

    a, b = st.columns(2)

    with a:
        st.markdown("""
        <div class="vx-panel">
            <div class="vx-eyebrow">MESSAGE INTELLIGENCE</div>
            <h3>Analyse a suspicious message</h3>
            <p class="vx-muted">
                Classify a message and review its learned model signals.
            </p>
        </div>
        """, unsafe_allow_html=True)

        if st.button("Open Message Scanner →", key="go_message", use_container_width=True):
            st.session_state["navigation_target"] = "Message Scanner"
            st.rerun()

    with b:
        st.markdown("""
        <div class="vx-panel">
            <div class="vx-eyebrow">URL INTELLIGENCE</div>
            <h3>Inspect a web address</h3>
            <p class="vx-muted">
                Review URL structure for common warning indicators.
            </p>
        </div>
        """, unsafe_allow_html=True)

        if st.button("Open URL Inspector →", key="go_url", use_container_width=True):
            st.session_state["navigation_target"] = "URL Inspector"
            st.rerun()

    st.markdown("")
    st.info(
        "Dataset note: training and test metrics are calculated from a "
        "stratified 80/20 split of the UCI SMS Spam Collection. "
        "They are not a guarantee of real-world detection performance."
    )


# ============================================================
# MESSAGE SCANNER
# ============================================================

elif page == "Message Scanner":

    st.markdown("""
    <div class="vx-hero">
        <div class="vx-eyebrow">NLP / TEXT CLASSIFICATION</div>
        <div class="vx-hero-title">Message Threat Scanner</div>
        <div class="vx-hero-copy">
            Submit a message to the trained classifier. SENTINEL evaluates
            its text patterns and returns a spam-model score with
            interpretable learned features.
        </div>
    </div>
    """, unsafe_allow_html=True)

    message = st.text_area(
        "Message to analyse",
        height=170,
        placeholder=(
            "Example: Congratulations! You have won a prize. "
            "Click this link now to claim your reward..."
        ),
    )

    if st.button("⚡ Analyse Message", use_container_width=True):

        if len(message.strip()) < 3:
            st.warning("Please enter a message with at least 3 characters.")

        else:
            result = analyze_message(model, message, threshold)
            st.session_state.scan_count += 1
            st.session_state["last_message_result"] = result
            st.session_state["last_message_text"] = message

    if "last_message_result" in st.session_state:
        result = st.session_state["last_message_result"]
        score = result["spam_score"] * 100

        st.markdown(
            '<div class="vx-section">◈ Investigation Result</div>',
            unsafe_allow_html=True,
        )

        c1, c2, c3 = st.columns(3)

        with c1:
            show_stat(
                "MODEL SPAM SCORE",
                f"{score:.1f}%",
                "Model output for spam class",
            )

        with c2:
            show_stat(
                "CLASSIFICATION",
                result["prediction"].upper(),
                "Using your selected threshold",
            )

        with c3:
            show_stat(
                "RISK BAND",
                risk_band(score),
                "Score-based display category",
            )

        if result["prediction"] == "spam":
            st.error(
                "⚠️ The model classifies this message as potentially spam."
            )
        else:
            st.success(
                "✓ The model classifies this message as likely legitimate."
            )

        st.progress(min(1.0, max(0.0, result["spam_score"])))

        st.markdown("#### Learned Model Signals")

        if result["signals"]:
            signal_html = " ".join(
                f'<span class="vx-chip">{html.escape(signal)}</span>'
                for signal in result["signals"]
            )
            st.markdown(signal_html, unsafe_allow_html=True)
            st.caption(
                "These are features with positive learned contributions "
                "towards the spam class for this message. They are signals, "
                "not proof of fraud."
            )
        else:
            st.info(
                "The model did not identify strong positive spam features "
                "among the words it knows."
            )

        st.markdown("#### Score Breakdown")

        breakdown = pd.DataFrame({
            "Class": ["Spam", "Legitimate"],
            "Model Score": [
                result["spam_score"] * 100,
                result["ham_score"] * 100,
            ],
        })

        fig = px.bar(
            breakdown,
            x="Model Score",
            y="Class",
            orientation="h",
            color="Class",
            color_discrete_map={
                "Spam": "#ff5575",
                "Legitimate": "#21d4fd",
            },
            range_x=[0, 100],
        )

        fig.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            showlegend=False,
        )

        st.plotly_chart(fig, use_container_width=True)

        st.warning(
            "SENTINEL is a research prototype. A model score is not a "
            "verified probability of fraud. Do not use it as the sole "
            "basis for financial or security decisions."
        )


# ============================================================
# URL INSPECTOR
# ============================================================

elif page == "URL Inspector":

    st.markdown("""
    <div class="vx-hero">
        <div class="vx-eyebrow">WEB ADDRESS INTELLIGENCE</div>
        <div class="vx-hero-title">URL Risk Inspector</div>
        <div class="vx-hero-copy">
            Review a URL for structural warning signs such as
            shortened links, raw IP addresses, punycode and
            suspicious URL patterns.
        </div>
    </div>
    """, unsafe_allow_html=True)

    url_input = st.text_input(
        "Enter a URL",
        placeholder="https://example.com/login",
    )

    if st.button("🔎 Inspect URL", use_container_width=True):

        if not url_input.strip():
            st.warning("Enter a URL to inspect.")

        else:
            url_result = inspect_url(url_input)

            if url_result:
                st.session_state["last_url_result"] = url_result
                st.session_state["last_url_text"] = url_input

    if "last_url_result" in st.session_state:
        result = st.session_state["last_url_result"]
        score = result["score"]

        st.markdown(
            '<div class="vx-section">◈ URL Investigation</div>',
            unsafe_allow_html=True,
        )

        c1, c2, c3 = st.columns(3)

        with c1:
            show_stat("URL INDICATOR SCORE", f"{score}/100", "Heuristic score")

        with c2:
            show_stat("RISK BAND", risk_band(score), "Based on rule score")

        with c3:
            show_stat("HOST", result["host"][:25], "Parsed hostname")

        gauge = go.Figure(go.Indicator(
            mode="gauge+number",
            value=score,
            number={"suffix": "/100"},
            gauge={
                "axis": {"range": [0, 100]},
                "bar": {"color": "#21d4fd"},
                "steps": [
                    {"range": [0, 30], "color": "#123d3b"},
                    {"range": [30, 65], "color": "#56451d"},
                    {"range": [65, 100], "color": "#542638"},
                ],
            },
        ))

        gauge.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            height=260,
            margin=dict(l=25, r=25, t=25, b=10),
        )

        st.plotly_chart(gauge, use_container_width=True)

        st.markdown("#### Structural Findings")

        for finding in result["findings"]:
            st.markdown(f"- {finding}")

        st.warning(
            "This is a heuristic URL inspection tool. It does not open "
            "the URL, query threat-intelligence databases, or confirm "
            "whether a website is malicious. A low score does not mean "
            "a website is safe."
        )


# ============================================================
# BATCH CSV SCANNER
# ============================================================

elif page == "Batch Analysis":

    st.markdown("""
    <div class="vx-hero">
        <div class="vx-eyebrow">BULK MESSAGE INVESTIGATION</div>
        <div class="vx-hero-title">Batch Threat Analysis</div>
        <div class="vx-hero-copy">
            Upload a CSV containing message text. SENTINEL will classify
            every row and create an exportable investigation file.
        </div>
    </div>
    """, unsafe_allow_html=True)

    uploaded_csv = st.file_uploader(
        "Upload CSV file",
        type=["csv"],
        help=(
            "The CSV should contain a column named message, text, "
            "sms or content."
        ),
    )

    if uploaded_csv is not None:

        try:
            input_df = pd.read_csv(uploaded_csv)

            candidate_columns = [
                "message", "text", "sms", "content"
            ]

            matching_column = next(
                (
                    column for column in input_df.columns
                    if str(column).strip().lower() in candidate_columns
                ),
                None,
            )

            if matching_column is None and len(input_df.columns) > 0:
                matching_column = input_df.columns[0]

            if matching_column is None:
                st.error("The uploaded CSV does not contain a usable column.")

            else:
                st.markdown(
                    f"**Using text column:** `{matching_column}`"
                )

                st.dataframe(input_df.head(8), use_container_width=True)

                if st.button(
                    "⚡ Scan All Messages",
                    use_container_width=True,
                ):

                    texts = (
                        input_df[matching_column]
                        .fillna("")
                        .astype(str)
                        .tolist()
                    )

                    predictions = model.predict(texts)
                    probabilities = model.predict_proba(texts)

                    spam_index = list(model.classes_).index("spam")
                    spam_scores = probabilities[:, spam_index] * 100

                    output = input_df.copy()
                    output["sentinel_prediction"] = predictions
                    output["spam_model_score_percent"] = np.round(
                        spam_scores, 2
                    )
                    output["score_band"] = [
                        risk_band(float(value))
                        for value in spam_scores
                    ]

                    st.session_state["batch_output"] = output

        except Exception as error:
            st.error(f"Could not read this CSV: {error}")

    if "batch_output" in st.session_state:
        output = st.session_state["batch_output"]

        spam_total = int(
            (output["sentinel_prediction"] == "spam").sum()
        )
        ham_total = int(
            (output["sentinel_prediction"] == "ham").sum()
        )

        c1, c2, c3 = st.columns(3)

        c1.metric("Messages Analysed", len(output))
        c2.metric("Potential Spam", spam_total)
        c3.metric("Likely Legitimate", ham_total)

        st.markdown("#### Batch Results")

        st.dataframe(output, use_container_width=True)

        chart_data = pd.DataFrame({
            "Category": ["Potential spam", "Likely legitimate"],
            "Messages": [spam_total, ham_total],
        })

        fig = px.bar(
            chart_data,
            x="Category",
            y="Messages",
            color="Category",
            color_discrete_map={
                "Potential spam": "#ff5575",
                "Likely legitimate": "#21d4fd",
            },
        )

        fig.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            showlegend=False,
        )

        st.plotly_chart(fig, use_container_width=True)

        csv_bytes = output.to_csv(index=False).encode("utf-8")

        st.download_button(
            "⬇️ Download Investigation CSV",
            data=csv_bytes,
            file_name="sentinel_ai_batch_report.csv",
            mime="text/csv",
            use_container_width=True,
        )


# ============================================================
# MODEL LAB
# ============================================================

elif page == "Model Lab":

    st.markdown("""
    <div class="vx-hero">
        <div class="vx-eyebrow">MODEL EVALUATION / RESEARCH</div>
        <div class="vx-hero-title">Machine Learning Laboratory</div>
        <div class="vx-hero-copy">
            Review the model architecture, training split and
            classification performance on held-out data.
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("### Model Architecture")

    st.markdown("""
    <div class="vx-panel">
        <p><b>Input:</b> Labelled SMS text</p>
        <p><b>Feature extraction:</b> TF-IDF word and bigram features</p>
        <p><b>Classifier:</b> Logistic Regression with balanced class weights</p>
        <p><b>Output:</b> ham or spam prediction and class scores</p>
        <p><b>Evaluation:</b> Stratified 80/20 train/test split</p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("### Held-out Test Performance")

    a, b, c, d = st.columns(4)

    a.metric("Accuracy", f"{metrics['accuracy']:.2%}")
    b.metric("Precision", f"{metrics['precision']:.2%}")
    c.metric("Recall", f"{metrics['recall']:.2%}")
    d.metric("F1 Score", f"{metrics['f1']:.2%}")

    st.caption(
        f"Training records: {metrics['train_size']:,} | "
        f"Test records: {metrics['test_size']:,}"
    )

    matrix = metrics["confusion"]

    matrix_df = pd.DataFrame(
        matrix,
        index=["Actual legitimate", "Actual spam"],
        columns=["Predicted legitimate", "Predicted spam"],
    )

    st.markdown("### Confusion Matrix")

    fig = px.imshow(
        matrix_df,
        text_auto=True,
        color_continuous_scale="Blues",
        aspect="auto",
    )

    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        coloraxis_showscale=False,
    )

    st.plotly_chart(fig, use_container_width=True)

    st.markdown("### Dataset Profile")

    label_counts = dataset["label"].value_counts().rename_axis(
        "Class"
    ).reset_index(name="Messages")

    st.dataframe(label_counts, use_container_width=True)

    st.info(
        "The held-out test metrics measure performance on this dataset "
        "split. They do not establish performance on every language, "
        "region, message style or future scam campaign."
    )


# ============================================================
# ABOUT
# ============================================================

elif page == "About":

    st.markdown("""
    <div class="vx-hero">
        <div class="vx-eyebrow">PROJECT INFORMATION</div>
        <div class="vx-hero-title">About SENTINEL AI</div>
        <div class="vx-hero-copy">
            A defensive security research prototype combining
            supervised text classification, model interpretation
            and rule-based URL inspection.
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("### Technology Stack")

    st.markdown("""
    - **Python** — application and data processing
    - **Scikit-learn** — model training and evaluation
    - **TF-IDF** — text feature extraction
    - **Logistic Regression** — binary message classifier
    - **Pandas / NumPy** — tabular data processing
    - **Plotly** — interactive visual analytics
    - **Streamlit** — interactive web application
    """)

    st.markdown("### Dataset and Attribution")

    st.write(
        "Training data: UCI SMS Spam Collection, a labelled collection "
        "of SMS messages for spam research."
    )

    st.markdown(
        "[UCI Machine Learning Repository — SMS Spam Collection]"
        "(https://archive.ics.uci.edu/dataset/228/sms+spam+collection)"
    )

    st.write(
        "Almeida, T. & Hidalgo, J. (2011). "
        "SMS Spam Collection. UCI Machine Learning Repository. "
        "DOI: 10.24432/C5CC84."
    )

    st.markdown("### Important Limitations")

    st.warning("""
    SENTINEL AI is an educational and research prototype.

    Its message classifier learns from an SMS dataset and may make
    mistakes on new, unusual or multilingual messages.

    Its URL inspector uses basic structural heuristics. It does not
    query live threat feeds, browse websites, verify certificates or
    confirm malicious activity.

    Do not use this application as the sole basis for financial,
    legal or security decisions.
    """)


# ============================================================
# FOOTER
# ============================================================

st.markdown("---")

st.markdown(
    """
    <div style="text-align:center;color:#72839a;font-size:11px;">
        SENTINEL AI · DEFENSIVE THREAT INTELLIGENCE RESEARCH
        <br>
        Built with Python, Scikit-learn and Streamlit
    </div>
    """,
    unsafe_allow_html=True,
)