"""
app.py
Streamlit dashboard for the phishing detector. Reuses the exact same
pipeline logic as main.py (CLI) -- this is purely a UI layer on top.

Run with: python -m streamlit run app.py
"""

import os
import streamlit as st
import tempfile

from main import run_pipeline
from modules.url_analyzer import analyze_urls
from modules.ocr_scanner import extract_text_from_image, extract_urls_from_text
from modules.pdf_scanner import (
    extract_text, extract_link_annotations, extract_urls_from_text as extract_urls_from_pdf_text,
    check_pdf_risk_flags, render_first_page_image
)
from modules.llm_agent import get_verdict_from_screenshot, get_verdict_from_pdf
from modules.feedback import log_correction, get_stats

from modules.history import get_all_analyses, get_stats as get_history_stats
from modules.malware_scanner import full_malware_scan


st.set_page_config(
    page_title="PhishGuard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

col1, col2 = st.columns([1, 5])
with col1:
    st.markdown("# 🛡️")
with col2:
    st.markdown("## PhishGuard AI")
    st.caption("AI-powered phishing triage — email, screenshot, PDF, and malware scanning")
st.divider()

if not os.environ.get("GEMINI_API_KEY"):
    st.error("GEMINI_API_KEY not set. Add it to your .env file.")
    st.stop()

st.set_page_config(page_title="Phishing Detector", layout="wide")

# ---------- Sidebar (add this block) ----------
from modules.history import get_stats as get_history_stats  # add this import near your other imports too

with st.sidebar:
    st.markdown("### 🛡️ PhishGuard AI")
    st.caption("Deterministic checks + Gemini reasoning")
    st.divider()
    stats = get_history_stats()
    st.metric("Total scanned", stats["total"])
    st.metric("Phishing caught", stats["by_verdict"].get("phishing", 0))

st.title("AI-powered phishing email triage")

if not os.environ.get("GEMINI_API_KEY"):
    st.error("GEMINI_API_KEY not set. Add it to your .env file.")
    st.stop()


tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(
    [
        "Upload .eml",
        "Paste raw email",
        "Upload screenshot",
        "Upload PDF",
        "Want to Know previous checks?",
        "Feedback stats",
    ]
)

# ---------- helpers ----------
def render_verdict(v: dict):
    verdict = v.get("verdict", "unknown")
    confidence = v.get("confidence", 0)

    if verdict == "phishing":
        st.error(f"🚨 PHISHING DETECTED — {confidence}% confidence")
    elif verdict == "suspicious":
        st.warning(f"⚠️ SUSPICIOUS — {confidence}% confidence")
    elif verdict == "legitimate":
        st.success(f"✅ LEGITIMATE — {confidence}% confidence")
    else:
        st.info(f"❓ UNKNOWN — could not determine a verdict")

    if v.get("techniques_detected"):
        st.write("**Techniques detected:**", ", ".join(v["techniques_detected"]))

    st.write("**Reasoning:**")
    for point in v.get("reasoning", []):
        st.write(f"- {point}")

def render_evidence(ev: dict):
    with st.container(border=True):
        st.write("**Evidence Summary**")
        st.json(ev)

def correction_buttons(subject: str, predicted: str, key_prefix: str):
    st.write("Was this verdict correct?")
    c1, c2, c3 = st.columns(3)
    for col, label in zip((c1, c2, c3), ("phishing", "suspicious", "legitimate")):
        if col.button(f"Mark as {label}", key=f"{key_prefix}_{label}"):
            log_correction(subject, predicted, label)
            st.success(f"Logged correction: actual = {label}")

# ---------- Tab 1: .eml upload ----------
tmp_path = None
with tab1:
    uploaded = st.file_uploader("Upload a .eml file", type=["eml"])
    if uploaded:
        with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as tmp:
            tmp.write(uploaded.read())
            tmp_path = tmp.name

if tmp_path is not None:
    with st.status("Analyzing email...", expanded=True) as status:
        st.write("🔍 Parsing headers...")
        st.write("🔗 Checking URLs for typosquatting...")
        st.write("🧠 Running AI reasoning...")
        result = run_pipeline(tmp_path)
        status.update(label="Analysis complete!", state="complete")

    render_verdict(result["verdict"])
    render_evidence(result["evidence"])
    correction_buttons(result["subject"], result["verdict"].get("verdict", "unknown"), "eml")


# ---------- Tab 2: paste raw email ----------
with tab2:
    st.caption("Paste the full raw source (headers + body) for best results -- most email clients have a 'Show original' or 'View source' option.")
    raw_text = st.text_area("Raw email source", height=300)
    if st.button("Analyze pasted email") and raw_text.strip():
        with tempfile.NamedTemporaryFile(suffix=".eml", delete=False, mode="w") as tmp:
            tmp.write(raw_text)
            tmp_path = tmp.name

        with st.spinner("Running pipeline..."):
            result = run_pipeline(tmp_path)

        render_verdict(result["verdict"])
        render_evidence(result["evidence"])
        correction_buttons(result["subject"], result["verdict"].get("verdict", "unknown"), "paste")

# ---------- Tab 3: screenshot ----------
with tab3:
    st.caption("No headers available in a screenshot, so SPF/DKIM checks are skipped. Gemini analyzes the image directly plus OCR-extracted text and URLs.")
    img_file = st.file_uploader("Upload a screenshot", type=["png", "jpg", "jpeg"])
    if img_file:
        image_bytes = img_file.read()
        st.image(image_bytes, caption="Uploaded screenshot", width=400)

        with st.spinner("Running OCR + analysis..."):
            ocr_text = extract_text_from_image(image_bytes)
            urls = extract_urls_from_text(ocr_text)
            url_analysis = analyze_urls(urls)
            verdict = get_verdict_from_screenshot(image_bytes, ocr_text, url_analysis)

        render_verdict(verdict)
        with st.expander("OCR-extracted text"):
            st.text(ocr_text)
        with st.expander("URL analysis"):
            st.json(url_analysis)
        correction_buttons("(screenshot)", verdict.get("verdict", "unknown"), "screenshot")

# ---------- Tab 4: PDF ----------
with tab4:
    st.caption("Checks visible text, clickable link annotations (which can differ from what's shown), embedded JavaScript/files, and renders page 1 for visual analysis.")
    pdf_file = st.file_uploader("Upload a PDF", type=["pdf"])
    if pdf_file:
        pdf_bytes = pdf_file.read()

        with st.spinner("Extracting text, links, and risk flags..."):
            text = extract_text(pdf_bytes)
            links = extract_link_annotations(pdf_bytes)
            urls_in_text = extract_urls_from_pdf_text(text)
            all_urls = list(dict.fromkeys(urls_in_text + [l["uri"] for l in links if l["uri"].startswith("http")]))
            url_analysis = analyze_urls(all_urls)
            risk_flags = check_pdf_risk_flags(pdf_bytes)
            page_image = render_first_page_image(pdf_bytes)

        st.image(page_image, caption="Page 1 (rendered)", width=400)

        with st.spinner("Running AI analysis..."):
            verdict = get_verdict_from_pdf(page_image, text, links, url_analysis, risk_flags)

        render_verdict(verdict)

        if risk_flags["flags"]:
            st.warning("Structural risk flags:\n" + "\n".join(f"- {f}" for f in risk_flags["flags"]))

        with st.expander("Link annotations (actual click targets)"):
            st.json(links)
        with st.expander("Extracted text"):
            st.text(text)
        with st.expander("URL analysis"):
            st.json(url_analysis)

        correction_buttons(pdf_file.name, verdict.get("verdict", "unknown"), "pdf")

#  ---------- Tab 5: History ----------
with tab5:
    st.write("**Recent analyses:**")
    records = get_all_analyses(limit=50)
    for r in records:
        color = {"phishing": "red", "suspicious": "orange", "legitimate": "green"}.get(r["verdict"], "gray")
        with st.expander(f":{color}[{r['verdict'].upper()}] — {r['identifier']} ({r['timestamp'][:19]})"):
            st.write(f"Confidence: {r['confidence']}% | Source: {r['source_type']}")
            st.json({"evidence": r["evidence_json"], "malware_flags": r["malware_flags"]})


# ---------- Tab 6: feedback stats ----------
with tab6:
    stats = get_stats()
    st.metric("Total corrections logged", stats["total_corrections"])
    if stats["total_corrections"] > 0:
        st.write("**Corrections by original prediction:**")
        st.bar_chart(stats["by_predicted_verdict"])
        st.write("**Most recent corrections:**")
        st.json(stats["most_recent"])

