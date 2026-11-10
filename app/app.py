"""Streamlit web UI for phishing URL detection."""

import json
import os

import pandas as pd
import streamlit as st

# App title
st.set_page_config(page_title="Phishing URL Detector", page_icon="🛡️", layout="centered")

st.title("Phishing URL Detector 🛡️")
st.markdown(
    "Enter a URL to check if it's likely to be a phishing site. "
    "URLs are analyzed **as text only** and never visited or fetched."
)
st.caption("Safety note: This tool uses machine learning heuristics from URL structure. Always verify independently.")

# Note about domain-only scoring
st.info("This model scores the domain only; paths, query strings and https/www are ignored.")

# URL input with session state for example buttons
if "url_input" not in st.session_state:
    st.session_state.url_input = ""

def set_example_url(url_value: str):
    st.session_state.url_input = url_value

url = st.text_input("Enter URL to analyze:", placeholder="https://example.com", key="url_input", max_chars=2048)

# Example URLs - use on_click to fill the text box
st.markdown("---")
st.markdown("**Example URLs:**")
col1, col2 = st.columns(2)
with col1:
    st.button("🔒 Legitimate: Google", on_click=set_example_url, args=("https://www.google.com/search?q=python",))
with col2:
    st.button("⚠️ Suspicious: PayPal-like", on_click=set_example_url, args=("https://secure-login.paypal.verify-update.tk/login.php",))

# Button
check = st.button("Check URL", type="primary")

# Show result if URL provided
if check and url.strip():
    # Import prediction and explanation modules
    from phishdetect.predict import predict_url
    from phishdetect.explain import explain_url
    from phishdetect.features import extract_features, feature_context
    
    result = predict_url(url.strip())
    features = extract_features(url.strip())
    ctx = feature_context(url.strip())
    
    # Try to get SHAP explanation, fall back to empty if it fails
    try:
        explanation = explain_url(url.strip())
    except Exception:
        explanation = {"reasons": [], "shap_values": [], "base_value": 0.0}
    
    # Check for hosting platform
    on_hosting_platform = features.get("on_known_hosting_platform", 0) == 1.0
    
    # Determine risk level with platform consideration
    prob_pct = result["probability"] * 100
    risk_level = result["risk_level"]
    if on_hosting_platform and risk_level == "high":
        risk_level = "uncertain"
    
    # Result card
    st.markdown("---")
    st.subheader("Result")
    
    col1, col2 = st.columns([2, 1])
    with col1:
        if result["label"] == "phishing":
            if on_hosting_platform:
                st.warning("⚠️ **Phishing Detected** (but domain is on a shared hosting platform)")
            else:
                st.error("🚨 **Phishing Detected!**")
        else:
            st.success("✅ **Likely Legitimate**")
    
    with col2:
        # delta_color="off" prevents green/red coloring based on value
        st.metric("Risk Level", risk_level.upper(),
                  f"Probability: {prob_pct:.1f}%", delta_color="off")

    # Progress bar
    st.progress(result["probability"])

    # Caption: estimated risk, not a guarantee
    st.caption("Estimated risk, not a guarantee.")

    # Platform warning if applicable
    if on_hosting_platform:
        st.warning(
            "⚠️ **Platform Notice**: This domain is hosted on a known shared platform "
            "(e.g., GitHub Pages, Netlify, Vercel, etc.). On such platforms, the domain alone "
            "cannot reliably separate legitimate from malicious sites, as both can coexist. "
            "The risk level has been adjusted to 'uncertain'."
        )

    # Red flags (rule-based, not from the model)
    st.markdown("---")
    st.markdown("### Red Flags (Rule-based, Not from the Model)")
    
    red_flags = []
    if features.get("is_suspicious_tld", 0) == 1:
        red_flags.append(("Suspicious TLD", f"Uses suspicious TLD: .{ctx.get('tld', 'unknown')}"))
    if features.get("brand_in_subdomain", 0) == 1:
        brands = ctx.get('brands', [])
        red_flags.append(("Brand Lookalike", f"Contains brand name in subdomain: {', '.join(brands) if brands else 'detected'}"))
    if features.get("suspicious_keyword_count", 0) > 0:
        kws = ctx.get('suspicious_keywords', [])
        red_flags.append(("Suspicious Keywords", f"Found {int(features['suspicious_keyword_count'])} suspicious keyword(s): {', '.join(kws) if kws else 'detected'}"))
    if features.get("has_ip_address", 0) == 1:
        red_flags.append(("IP Address Host", "Hostname is an IP address rather than a domain name"))
    if features.get("uses_punycode", 0) == 1:
        red_flags.append(("Punycode", "Uses punycode encoding (xn--) for internationalized domain"))
    if features.get("uses_url_shortener", 0) == 1:
        shortener = ctx.get('shortener', '')
        red_flags.append(("URL Shortener", f"Uses known URL shortener: {shortener}" if shortener else "Uses a known URL shortener"))
    
    if red_flags:
        for flag_name, flag_detail in red_flags:
            st.markdown(f"- **{flag_name}**: {flag_detail}")
    else:
        st.info("No obvious rule-based red flags detected.")

    # Why? section (model-based SHAP explanation)
    st.markdown("---")
    st.markdown("### Why? (Model-based Feature Contributions)")

    reasons = explanation.get("reasons", [])
    if reasons:
        # Create DataFrame for display
        df = pd.DataFrame(reasons)
        positive = df["impact"] > 0
        df["color"] = positive.map({True: "#e74c3c", False: "#3498db"})
        df["impact_abs"] = df["impact"].abs()
        df = df.sort_values("impact_abs", ascending=True)

        # Bar chart with colored bars
        import altair as alt
        chart = alt.Chart(df).mark_bar().encode(
            x=alt.X("feature:N", sort=None),
            y=alt.Y("impact:Q"),
            color=alt.Color("color:N", scale=alt.Scale(range=["#3498db", "#e74c3c"]), legend=None),
        )
        st.altair_chart(chart, use_container_width=True)
        # Note: Streamlit bar_chart doesn't support per-bar colors natively,
        # so we show the colors in the legend via the DataFrame
        with st.expander("Detailed Reasons"):
            for r in reasons:
                direction = "↑ phishing" if r["impact"] > 0 else "↓ legitimate"
                st.markdown(f"- **{r['feature']}**: {r['explanation']} ({direction})")
    else:
        st.info("Not enough data for reasons.")

# Sidebar
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
METADATA_PATH = os.path.join(PROJECT_ROOT, "models", "metadata.json")
METRICS_PATH = os.path.join(PROJECT_ROOT, "reports", "metrics.json")

try:
    with open(METADATA_PATH) as f:
        metadata = json.load(f)
except Exception:
    metadata = {}

try:
    with open(METRICS_PATH) as f:
        metrics = json.load(f)
except Exception:
    metrics = {}

st.sidebar.markdown("---")
st.sidebar.markdown("## Model Info")

model_type = metadata.get("deployed_model", "LogisticRegression")
feature_count = metadata.get("feature_count", 16)
threshold = metadata.get("threshold", 0.5)

st.sidebar.info(f"{model_type} with {feature_count} host-only features")
st.sidebar.markdown(f"**Decision threshold:** {threshold:.2f}")

# Show metrics for deployed model if available
model_key = model_type
if model_key in metrics.get("in_distribution_test", {}):
    m = metrics["in_distribution_test"][model_key]
    st.sidebar.markdown("**Test metrics (in-distribution):**")
    st.sidebar.markdown(f"- Accuracy: {m.get('accuracy', 0):.3f}")
    st.sidebar.markdown(f"- Precision: {m.get('precision', 0):.3f}")
    st.sidebar.markdown(f"- Recall: {m.get('recall', 0):.3f}")
    st.sidebar.markdown(f"- F1: {m.get('f1', 0):.3f}")
    st.sidebar.markdown(f"- ROC-AUC: {m.get('roc_auc', 0):.3f}")
    st.sidebar.markdown(f"- FPR: {m.get('fpr', 0):.4f}")

    # Show independent-test FPR and recall with sample sizes
    ind = metrics.get("independent_test", {})
    ratio_k = "ratio_1_to_1"
    if ratio_k in ind:
        ind_data = ind[ratio_k]
        ind_fpr = ind_data.get("fpr", None)
        ind_recall = ind_data.get("recall", None)
        phish_n = ind_data.get("phishing_count", "?")
        legit_n = ind_data.get("legitimate_count", "?")
        if ind_fpr is not None:
            st.sidebar.markdown(f"**Independent-test FPR (1:1, n={legit_n}):** {ind_fpr:.4f}")
        if ind_recall is not None:
            st.sidebar.markdown(f"**Independent-test Recall (1:1, n={phish_n}):** {ind_recall:.4f}")
    elif "overall" in ind:
        ind_data = ind["overall"]
        ind_fpr = ind_data.get("fpr", None)
        ind_recall = ind_data.get("recall", None)
        phish_n = ind_data.get("phishing_count", "?")
        legit_n = ind_data.get("legitimate_count", "?")
        if ind_fpr is not None:
            st.sidebar.markdown(f"**Independent-test FPR (n={legit_n}):** {ind_fpr:.4f}")
        if ind_recall is not None:
            st.sidebar.markdown(f"**Independent-test Recall (n={phish_n}):** {ind_recall:.4f}")

st.sidebar.markdown("**Features:**")
st.sidebar.markdown("- Host length, dots, hyphens, underscores")
st.sidebar.markdown("- Digits, digit ratio, subdomains")
st.sidebar.markdown("- Suspicious TLD, punycode, IP host")
st.sidebar.markdown("- URL shortener, brand in subdomain")
st.sidebar.markdown("- Suspicious keywords, entropy")
st.sidebar.markdown("- Consonant and digit runs")

st.sidebar.markdown("---")
st.sidebar.markdown("**Resources**")
st.sidebar.markdown("[GitHub Repo](https://github.com/yourusername/phishing-url-detector)")
st.sidebar.markdown("Built with ❤️ using scikit-learn, FastAPI, and Streamlit")
