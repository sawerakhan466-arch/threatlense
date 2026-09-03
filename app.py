"""
app.py
------
ThreatLens - AI-Powered IP, Domain & URL Security Analyzer.

This module is responsible ONLY for:
    * Streamlit UI
    * User input (IOC type, knowledge level, IOC value)
    * Validation orchestration (delegated to sources.py helpers)
    * Iterating through the SOURCES registry (no per-source branching)
    * Aggregating results
    * Building the Gemini prompt
    * Calling Gemini
    * Displaying results

app.py knows that SOURCES exist. It does NOT know how individual
sources work - that logic lives entirely in sources.py.
"""

from __future__ import annotations

import os
from typing import Any
import time
import streamlit as st

from sources import SOURCES, detect_ioc_type, is_valid_ioc

try:
    from google import genai
except ImportError:  # Gemini SDK missing - handled gracefully at call time
    genai = None


# --------------------------------------------------------------------------
# Page setup
# --------------------------------------------------------------------------

st.set_page_config(
    page_title="ThreatLens",
    page_icon="🔍",
    layout="centered",
)

VERDICT_COLORS = {
    "SAFE": "#1e7e34",
    "SUSPICIOUS": "#b8860b",
    "MALICIOUS": "#b02a2a",
    "UNKNOWN": "#6c757d",
    "ERROR": "#6c757d",
}

VERDICT_BG = {
    "SAFE": "#e6f4ea",
    "SUSPICIOUS": "#fff4e0",
    "MALICIOUS": "#fbe7e7",
    "UNKNOWN": "#eceff1",
    "ERROR": "#f1f1f1",
}


# --------------------------------------------------------------------------
# Gemini helpers
# --------------------------------------------------------------------------

def _get_gemini_api_key() -> str | None:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        try:
            if "GEMINI_API_KEY" in st.secrets:
                api_key = st.secrets["GEMINI_API_KEY"]
        except Exception:
            pass
    return api_key


def build_gemini_prompt(
    ioc: str,
    ioc_type: str,
    knowledge_level: str,
    results: dict[str, dict[str, Any]],
    overall_verdict: str,
    overall_risk: int,
) -> str:
    """Build a knowledge-level-specific prompt for Gemini. No secrets included."""

    findings_lines = []
    for source_name, result in results.items():
        findings_lines.append(
            f"- {source_name}: verdict={result['verdict']}, "
            f"risk_score={result['risk_score']}, "
            f"error={result['error']}, "
            f"raw_data={result['raw_data']}"
        )
    findings_block = "\n".join(findings_lines)

    base_context = f"""
You are a cybersecurity analysis assistant. Analyze the following IOC
(Indicator of Compromise) using ONLY the data provided below. Do not
invent facts that are not present in this data. If information is
unavailable from a source, explicitly say so.

IOC: {ioc}
IOC Type: {ioc_type}
Overall Verdict: {overall_verdict}
Overall Risk Score: {overall_risk}/100

Source findings:
{findings_block}

Clearly distinguish between "Observed evidence" (what the sources
actually reported) and "AI interpretation" (your reasoning about it).

Structure your response with these exact section headers:
Summary
Risk Assessment
Key Indicators
Recommended Action
Limitations

Keep the response concise and suitable for display in a dashboard.
"""

    if knowledge_level == "Beginner":
        instruction = """
Explain this security analysis as if the user has little or no
cybersecurity background. Use simple, plain language, short
sections, and practical advice. Briefly explain what VirusTotal and
WHOIS are and why they were used. Avoid unnecessary jargon. Clearly
state that this result is an assessment, not an absolute guarantee.
"""
    elif knowledge_level == "Intermediate":
        instruction = """
Explain the verdict for a user with some cybersecurity familiarity.
Interpret the VirusTotal detection ratio and relevant WHOIS
indicators. Explain why the risk score was produced, identify
important indicators, and provide clear recommended next steps.
Use moderate technical terminology, briefly explained where useful.
"""
    else:  # Expert
        instruction = """
Provide a concise, technical analysis for an expert audience. Discuss
detection ratios and source confidence, meaningful IOC indicators,
and registration/infrastructure metadata. Explain uncertainty and
limitations. Do not explain basic cybersecurity concepts. Provide
practical investigation recommendations. Be technically useful
without being unnecessarily verbose.
"""

    return base_context + "\n" + instruction


def call_gemini(prompt: str) -> str:
    """Call Gemini with clean model strings and detailed error handling."""

    if genai is None:
        raise RuntimeError("google-genai package is not installed.")

    api_key = _get_gemini_api_key()

    if not api_key:
        raise RuntimeError("GEMINI_API_KEY is not configured.")

    client = genai.Client(api_key=api_key)

    # Standard model strings for the new google-genai SDK
    models = [
      
        model = "gemini-3.5-flash"
    ]
    
    last_error = ""

    for model_name in models:
        for attempt in range(3):
            try:
                response = client.models.generate_content(
                    model=model_name,
                    contents=prompt,
                )

                if response and response.text:
                    return response.text

            except Exception as exc:
                last_error = str(exc)
                
                # Check for transient network/server errors
                is_transient = any(
                    err in last_error for err in ["503", "UNAVAILABLE", "429", "RESOURCE_EXHAUSTED", "Overloaded"]
                )

                if is_transient and attempt < 2:
                    time.sleep(2 * (attempt + 1))
                    continue
                
                # Move to the next fallback model if 404 or persistent error occurs
                break

    raise RuntimeError(f"Could not connect to Gemini API. Last error: {last_error}")
# --------------------------------------------------------------------------
# Aggregation helpers
# --------------------------------------------------------------------------

def compute_overall(results: dict[str, dict[str, Any]]) -> tuple[str, int]:
    """Derive an overall verdict/risk score from all successful source results."""
    valid_scores = [
        r["risk_score"] for r in results.values() if r["verdict"] not in ("ERROR", "UNKNOWN")
    ]

    if not valid_scores:
        return "UNKNOWN", 0

    overall_risk = int(round(max(valid_scores)))  # most severe source wins
    if overall_risk >= 60:
        overall_verdict = "MALICIOUS"
    elif overall_risk >= 30:
        overall_verdict = "SUSPICIOUS"
    else:
        overall_verdict = "SAFE"

    return overall_verdict, overall_risk


def render_verdict_badge(verdict: str) -> str:
    color = VERDICT_COLORS.get(verdict, "#6c757d")
    bg = VERDICT_BG.get(verdict, "#eceff1")
    return (
        f'<span style="background-color:{bg}; color:{color}; '
        f'padding:4px 12px; border-radius:12px; font-weight:600; '
        f'font-size:0.9rem;">{verdict}</span>'
    )


def sanitize_raw_data(raw_data: dict[str, Any]) -> dict[str, Any]:
    """Strip any accidental sensitive-looking keys before display."""
    banned_terms = ("key", "token", "auth", "secret", "credential", "password")
    return {
        k: v
        for k, v in raw_data.items()
        if not any(term in k.lower() for term in banned_terms)
    }


# --------------------------------------------------------------------------
# UI
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# Personal signature — Sawera → "100era" (سو / sau = 100 in Urdu/Hindi)
# --------------------------------------------------------------------------

with st.sidebar:
    st.markdown(
        """
        <div style="text-align:center; padding: 12px 0 20px 0;">
            <div style="font-size:1.9rem; font-weight:800; letter-spacing:0.5px;">
                <span style="color:#c83f70;">100era</span>
            </div>
            <div style="font-size:0.85rem; font-weight:600; color:#c83f70; margin-top:3px;">
                built &amp; secured by Sawera
            </div>
        </div>
        <hr style="margin:0 0 16px 0; opacity:0.15;">
        """,
        unsafe_allow_html=True,
    )
    st.caption("🔍 **ThreatLens**")
    st.caption("AI-Powered IOC Security Analyzer")

st.markdown(
    '<h1 style="color:#C11C84;">🔍 ThreatLens</h1>',
    unsafe_allow_html=True
)

st.markdown(
    '<p style="color:#D85A9F; font-size:1.05rem;">AI-Powered IP, Domain & URL Security Analyzer</p>',
    unsafe_allow_html=True
)

st.divider()

col1, col2 = st.columns(2)
with col1:
    ioc_type = st.selectbox("IOC Type", options=["IP", "Domain", "URL"])
with col2:
    knowledge_level = st.selectbox(
        "Knowledge Level", options=["Beginner", "Intermediate", "Expert"]
    )

placeholder_map = {
    "IP": "8.8.8.8",
    "Domain": "example.com",
    "URL": "https://example.com/login",
}
ioc_input = st.text_input(
    "Enter IP, domain, or URL", placeholder=placeholder_map[ioc_type]
)

analyze_clicked = st.button("🔎 Analyze IOC", type="primary", use_container_width=True)

st.divider()

if analyze_clicked:
    if not ioc_input or not ioc_input.strip():
        st.error("Please enter an IP, domain, or URL to analyze.")
    elif not is_valid_ioc(ioc_input.strip(), ioc_type):
        detected = detect_ioc_type(ioc_input.strip())
        st.error(
            f"'{ioc_input}' does not look like a valid {ioc_type}. "
            f"(Detected type: {detected})"
        )
    else:
        ioc = ioc_input.strip()

        # Generic orchestration - no source-specific branching.
        results: dict[str, dict[str, Any]] = {}
        with st.spinner("Querying intelligence sources..."):
            for source_name, source_function in SOURCES.items():
                try:
                    results[source_name] = source_function(ioc, ioc_type)
                except Exception as exc:  # absolute safety net
                    results[source_name] = {
                        "source": source_name,
                        "verdict": "ERROR",
                        "risk_score": 0,
                        "raw_data": {},
                        "error": f"Unexpected failure: {exc}",
                    }

        overall_verdict, overall_risk = compute_overall(results)

        # ---------------- Overall summary ----------------
        st.subheader("Overall Analysis")
        oc1, oc2, oc3 = st.columns(3)
        oc1.metric("IOC", ioc)
        oc2.metric("Type", ioc_type)
        with oc3:
            st.markdown("**Overall Risk**")
            st.markdown(render_verdict_badge(overall_verdict), unsafe_allow_html=True)
            st.caption(f"Score: {overall_risk}/100")

        st.divider()

        # ---------------- Individual source results ----------------
        st.subheader("Source Results")
        for source_name, result in results.items():
            with st.container(border=True):
                sc1, sc2, sc3 = st.columns([2, 2, 2])
                sc1.markdown(f"**{result['source']}**")
                with sc2:
                    st.markdown(render_verdict_badge(result["verdict"]), unsafe_allow_html=True)
                sc3.markdown(f"Risk Score: **{result['risk_score']}/100**")
                if result["error"]:
                    st.warning(result["error"])

        # ---------------- Gemini AI insight ----------------
        st.divider()
        st.subheader("🤖 AI Security Insight")

        prompt = build_gemini_prompt(
            ioc, ioc_type, knowledge_level, results, overall_verdict, overall_risk
        )

        try:
            with st.spinner("Generating AI insight..."):
                ai_text = call_gemini(prompt)
            with st.container(border=True):
                st.caption("AI-generated interpretation of the collected source data.")
                st.markdown(ai_text)
        except Exception as exc:
            st.warning("AI insight is currently unavailable.")
            st.caption(f"Gemini error: {exc}")

        # ---------------- Raw data (expandable) ----------------
        st.divider()
        with st.expander("🔎 View Source Details"):
            for source_name, result in results.items():
                st.markdown(f"**{source_name}**")
                sanitized = sanitize_raw_data(result.get("raw_data", {}))
                if sanitized:
                    st.json(sanitized)
                else:
                    st.caption("No additional data available.")
else:
    st.info("Select an IOC type and knowledge level, enter a value, then click Analyze IOC.")


# --------------------------------------------------------------------------
# Footer signature
# --------------------------------------------------------------------------

st.markdown(
    """
    <div style="text-align:center; padding-top:32px; opacity:0.85; font-size:0.8rem;">
        Crafted with 🔍 by 
        <span style="color:#c83f70; font-size:1.05rem; font-weight:700;">100era</span>
    </div>
    """,
    unsafe_allow_html=True,
)
