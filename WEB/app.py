"""
Kryptos — Web Edition
======================

Streamlit application entry point.

Launch:
    cd kryptos
    streamlit run WEB/app.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# -- Ensure project root is importable ------------------------------------
_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

# -- Ensure WEB/ directory is importable ----------------------------------
_web_root = str(Path(__file__).resolve().parent)
if _web_root not in sys.path:
    sys.path.insert(0, _web_root)

import streamlit as st  # noqa: E402

# ---------------------------------------------------------------------------
# Page config — must be the first Streamlit command
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="Kryptos",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ---------------------------------------------------------------------------
# Custom CSS to tighten up the UI and match the Local app dark theme
# ---------------------------------------------------------------------------

st.markdown(
    """
    <style>
    /* Accent colour overrides */
    .stButton > button[kind="primary"] {
        background-color: #e94560;
        border-color: #e94560;
    }
    .stButton > button[kind="primary"]:hover {
        background-color: #d63a54;
        border-color: #d63a54;
    }
    /* Smaller padding for containers */
    .stTabs [data-baseweb="tab-panel"] {
        padding-top: 1rem;
    }
    /* Header styling */
    .kryptos-header {
        text-align: center;
        padding: 1rem 0 0.5rem 0;
    }
    .kryptos-header h1 {
        font-size: 2.2rem;
        margin-bottom: 0.2rem;
    }
    .kryptos-header p {
        color: #a0a0b8;
        font-size: 0.95rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

st.markdown(
    """
    <div class="kryptos-header">
        <h1>🔐 Kryptos</h1>
        <p>AES-256-GCM Encryption &amp; Decryption Platform — Web Edition</p>
    </div>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

with st.sidebar:
    st.markdown("### About")
    st.markdown(
        "**Kryptos Web Edition** provides AES-256-GCM authenticated "
        "encryption with PBKDF2 key derivation and RSA-4096 hybrid "
        "encryption."
    )
    st.markdown("---")
    st.markdown("#### Security Notice")
    st.markdown(
        "• Keys exist **only** in your browser session.  \n"
        "• Closing the tab destroys all keys.  \n"
        "• Files encrypted here are fully compatible with the **Kryptos Desktop** app.  \n"
        "• Always back up your keys securely."
    )
    st.markdown("---")
    st.caption("Kryptos v1.0 — Web Edition")

# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------

from tabs.text_tab import render as render_text  # noqa: E402
from tabs.file_tab import render as render_file  # noqa: E402
from tabs.key_tab import render as render_keys   # noqa: E402

tab_text, tab_file, tab_keys = st.tabs(["📝 Text", "📁 File", "🔑 Keys"])

with tab_text:
    render_text()

with tab_file:
    render_file()

with tab_keys:
    render_keys()
