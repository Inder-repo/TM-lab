"""
STRIDE Threat Modeling - COMPLETE PRODUCTION VERSION (ENHANCED)
All 4 Workshops | Hidden Unlock Codes | Full Decompose | Threat Mapping | Enhanced Assessment
Aligned with Infosec Institute 4-Step Methodology:
  1. Design the threat model (DFD with interactors/modules/connections)
  2. Apply Zones of Trust (criticality labels + numerical 0-9 scale)
  3. Discover threats with STRIDE (rules-based by element type & zone direction)
  4. Explore mitigations and controls (OWASP Top 10 + compliance mapping)
"""

import streamlit as st
import streamlit.components.v1 as components_html
import base64
import hashlib
import hmac
import json
import math
import os
import re
import tempfile
import uuid
import pandas as pd
from graphviz import Digraph
from datetime import datetime
import random
from io import BytesIO

def _get_reportlab():
    """Lazy-load reportlab only when a PDF is actually requested."""
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                     PageBreak, Table, TableStyle)
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    return (letter, getSampleStyleSheet, ParagraphStyle, inch, colors,
            SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table,
            TableStyle, TA_CENTER, TA_LEFT)

st.set_page_config(
    page_title="STRIDE Threat Modeling Learning Lab",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ─────────────────────────────────────────────────────────────────────────────
# UNLOCK CODES - stored only as salted SHA-256 digests (no plaintext in source).
# To rotate a code:  hashlib.sha256(("stride-lab:" + NEW_CODE).encode()).hexdigest()
# ─────────────────────────────────────────────────────────────────────────────
_CODE_SALT = "stride-lab:"
WORKSHOP_CODE_HASHES = {
    "1": None,
    "2": "95b6136894dfc65f89a7ffb93daeb0c8b22590bf0199178a4b7cac03c68b2918",
    "3": "6c0e199c86eebe61ce83988daffc2137d9c846977aebadf8297ee77c73963a4c",
    "4": "dd8982302a0c0908185ffb8c2036d6e4deaf15314deb3618c1f8be1862ca4f2f",
}


def verify_unlock_code(ws_id, code):
    expected = WORKSHOP_CODE_HASHES.get(ws_id)
    if not expected:
        return False
    digest = hashlib.sha256((_CODE_SALT + (code or "").strip()).encode()).hexdigest()
    return hmac.compare_digest(digest, expected)

# ─────────────────────────────────────────────────────────────────────────────
# CSS
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""<style>
/* ═══ Design system: warm neutrals + one teal accent ═══════════════════════════════════ */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

:root{
  color-scheme: light;
  --bg:#F7F6F3; --surface:#FFFFFF; --surface-2:#FBFAF8; --sunken:#EFEDE8;
  --line:#E6E3DC; --line-2:#D5D1C8;
  --ink:#1E2522; --ink-2:#48524D; --muted:#7D857F;
  --accent:#1F6F66; --accent-hover:#185A53; --accent-ink:#0E3D38; --accent-soft:#E3EFEC; --accent-line:#B9D6D0;
  --ok:#3F7D5A;   --ok-soft:#EAF2EC;   --ok-line:#CFE3D6;
  --warn:#A8741A; --warn-soft:#F8F0DE; --warn-line:#EBDBB5;
  --bad:#B0413A;  --bad-soft:#F8E8E5;  --bad-line:#EBCBC6;
  --info:#3F6F8F; --info-soft:#E9EFF3; --info-line:#CBDCE6;
  --learn:#6A5A94; --learn-soft:#EFECF5; --learn-line:#D8D1E8;
  --dark:#232B28;
  --r:12px; --r-lg:16px;
  --shadow:0 1px 2px rgba(30,37,34,.04), 0 4px 14px rgba(30,37,34,.05);
  --shadow-hover:0 2px 4px rgba(30,37,34,.06), 0 8px 24px rgba(30,37,34,.08);
}

/* ── Base ─────────────────────────────────────────────────────────────────────────── */
html, body, [class*="css"], .stApp, button, input, textarea, select {
  font-family:'Inter', system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
}
html body .stApp, [data-testid="stAppViewContainer"], [data-testid="stMain"] { background:var(--bg); color:var(--ink); }
header[data-testid="stHeader"] { background:transparent; }
footer { visibility:hidden; }
.block-container { max-width:1240px; padding-top:2.2rem; padding-bottom:4rem; }
p, li { line-height:1.62; }
a { color:var(--accent); text-underline-offset:3px; }
code, pre, kbd, .mono { font-family:'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace !important; font-size:0.88em; }
::selection { background:var(--accent-soft); }

h1,h2,h3,h4,h5,h6 { font-family:'Inter', system-ui, sans-serif !important; color:var(--ink) !important; letter-spacing:-0.022em; }
h1 { font-size:2rem !important; font-weight:700 !important; line-height:1.15; }
h2 { font-size:1.5rem !important; font-weight:650 !important; padding-bottom:0; border:none; }
h3 { font-size:1.18rem !important; font-weight:650 !important; }
h4 { font-size:1.02rem !important; font-weight:650 !important; }
[data-testid="stCaptionContainer"], .stCaption { color:var(--muted) !important; }
hr { border:none; border-top:1px solid var(--line); margin:1.4rem 0; }

/* ── Buttons ──────────────────────────────────────────────────────────────────────── */
.stButton>button, .stDownloadButton>button, [data-testid="stFormSubmitButton"]>button {
  width:100%; border-radius:10px; font-weight:600; font-size:0.9rem; padding:0.55rem 1rem;
  background:var(--surface); color:var(--ink); border:1px solid var(--line-2);
  box-shadow:0 1px 0 rgba(30,37,34,.03); transition:background .15s, border-color .15s, box-shadow .15s;
}
.stButton>button:hover, .stDownloadButton>button:hover, [data-testid="stFormSubmitButton"]>button:hover {
  background:var(--surface-2); border-color:var(--ink-2); box-shadow:var(--shadow);
}
.stButton>button[kind="primary"], [data-testid="stBaseButton-primary"], [data-testid="stFormSubmitButton"]>button[kind="primaryFormSubmit"] {
  background:var(--accent) !important; color:#fff !important; border:1px solid var(--accent) !important;
}
.stButton>button[kind="primary"]:hover, [data-testid="stBaseButton-primary"]:hover, [data-testid="stFormSubmitButton"]>button[kind="primaryFormSubmit"]:hover {
  background:var(--accent-hover) !important; border-color:var(--accent-hover) !important;
}
.stButton>button:disabled { opacity:.5; cursor:not-allowed; }
button:focus-visible, a:focus-visible, [role="tab"]:focus-visible { outline:3px solid var(--accent-soft); outline-offset:1px; box-shadow:0 0 0 1px var(--accent); }

/* ── Inputs ───────────────────────────────────────────────────────────────────────── */
[data-baseweb="input"], [data-baseweb="textarea"], [data-baseweb="select"] > div { border-radius:10px !important; background:var(--surface) !important; border-color:var(--line-2) !important; }
[data-baseweb="input"]:focus-within, [data-baseweb="textarea"]:focus-within, [data-baseweb="select"] > div:focus-within { border-color:var(--accent) !important; box-shadow:0 0 0 3px var(--accent-soft) !important; }
[data-baseweb="tag"] { background:var(--accent-soft) !important; color:var(--accent-ink) !important; border-radius:8px !important; }
[data-baseweb="slider"] [role="slider"] { background:var(--accent) !important; border-color:var(--accent) !important; }
[data-testid="stWidgetLabel"] p { color:var(--ink-2); font-weight:500; }

/* ── Containers ───────────────────────────────────────────────────────────────────── */
[data-testid="stForm"] { background:var(--surface); border:1px solid var(--line); border-radius:var(--r-lg); padding:1.1rem 1.3rem; }
[data-testid="stExpander"] { background:var(--surface); border:1px solid var(--line) !important; border-radius:var(--r) !important; }
details { border-radius:var(--r) !important; border:1px solid var(--line) !important; background:var(--surface); }
details summary { font-weight:600; }
[data-testid="stDataFrame"] { border:1px solid var(--line); border-radius:var(--r); overflow:hidden; }
[data-testid="stAlert"] { border-radius:var(--r); border:1px solid var(--line); }
[data-testid="stMetric"] { background:var(--surface); border:1px solid var(--line); border-radius:var(--r); padding:12px 16px; }
.dataframe { border-radius:8px; overflow:hidden; }
.stProgress > div > div, [data-testid="stProgress"] div[role="progressbar"] > div { background:var(--accent) !important; border-radius:999px; }
.stProgress > div, [data-testid="stProgress"] div[role="progressbar"] { background:var(--sunken) !important; border-radius:999px; }

/* ── Tabs ─────────────────────────────────────────────────────────────────────────── */
.stTabs [data-baseweb="tab-list"] { gap:2px; border-bottom:1px solid var(--line); }
.stTabs [data-baseweb="tab"] { font-weight:500; font-size:0.9rem; padding:10px 14px; color:var(--ink-2); background:transparent; border-radius:8px 8px 0 0; }
.stTabs [data-baseweb="tab"]:hover { color:var(--ink); background:var(--sunken); }
.stTabs [aria-selected="true"] { color:var(--accent) !important; font-weight:650 !important; }
.stTabs [data-baseweb="tab-highlight"] { background:var(--accent) !important; height:2px; }
.stTabs [data-baseweb="tab-border"] { background:transparent !important; }

/* ── Cards ────────────────────────────────────────────────────────────────────────── */
.premium-card { background:var(--surface); border-radius:var(--r-lg); padding:20px 22px; margin:10px 0; border:1px solid var(--line); box-shadow:var(--shadow); transition:box-shadow .2s; }
.premium-card:hover { box-shadow:var(--shadow-hover); }
.concept-card { border-radius:var(--r); padding:16px 18px; margin:8px 0; border-left:4px solid; border-top:1px solid var(--line); border-right:1px solid var(--line); border-bottom:1px solid var(--line); background:var(--surface); }
.component-card { background:var(--surface); padding:14px 16px; border-radius:var(--r); border:1px solid var(--line); border-left:4px solid var(--accent); margin:6px 0; }
.zone-card { border-radius:var(--r); padding:14px 16px; margin:6px 0; border:1px solid var(--line); border-left:4px solid; }
.methodology-step { background:var(--surface); padding:18px 22px; border-radius:var(--r-lg); border:1px solid var(--line); margin:12px 0; box-shadow:var(--shadow); line-height:1.62; }
.methodology-step:hover { box-shadow:var(--shadow-hover); }
.metric-card { background:var(--surface); border-radius:var(--r); padding:16px; text-align:center; border:1px solid var(--line); box-shadow:var(--shadow); }
.metric-card .value { font-size:2rem; font-weight:700; color:var(--accent); letter-spacing:-0.02em; }
.metric-card .label { font-size:0.82rem; color:var(--muted); margin-top:4px; }
.diagram-container { overflow-x:auto; border:1px solid var(--line); border-radius:var(--r); padding:12px; background:var(--surface); box-shadow:var(--shadow); }
.flow-arrow { background:var(--accent-soft); color:var(--accent-ink); padding:6px 16px; border-radius:999px; display:inline-block; margin:4px; font-weight:500; font-size:0.88rem; }

/* ── Callouts (flat tint + accent bar) ────────────────────────────────────────────── */
.info-box, .success-box, .warning-box, .learning-box, .callout-box, .stride-rule-box, .owasp-box, .knowledge-check, .mitigation-card {
  padding:16px 20px; border-radius:var(--r); margin:12px 0; border:1px solid var(--line); border-left-width:4px; color:var(--ink); line-height:1.62;
}
.info-box { background:var(--info-soft); border-color:var(--info-line); border-left-color:var(--info); }
.success-box { background:var(--ok-soft); border-color:var(--ok-line); border-left-color:var(--ok); }
.warning-box { background:var(--warn-soft); border-color:var(--warn-line); border-left-color:var(--warn); }
.learning-box { background:var(--learn-soft); border-color:var(--learn-line); border-left-color:var(--learn); }
.callout-box { background:var(--warn-soft); border-color:var(--warn-line); border-left-color:var(--warn); }
.stride-rule-box { background:var(--learn-soft); border-color:var(--learn-line); border-left-color:var(--learn); }
.owasp-box { background:var(--accent-soft); border-color:var(--accent-line); border-left-color:var(--accent); }
.knowledge-check { background:var(--learn-soft); border-color:var(--learn-line); border-left-color:var(--learn); }
.knowledge-check h4 { color:var(--learn); margin-top:0; }
.mitigation-card { background:var(--warn-soft); border-color:var(--warn-line); border-left-color:var(--warn); padding:14px 16px; }
.practical-task { background:var(--surface); padding:18px 22px; border-radius:var(--r); border:1.5px dashed var(--accent-line); margin:12px 0; line-height:1.62; }
.expert-box { background:var(--dark); color:#ECEAE4; padding:18px 22px; border-radius:var(--r); border-left:4px solid #6FB3A8; margin:12px 0; line-height:1.62; }
.expert-box *, .real-world-box *, .key-concept *, .mastery-badge * { color:inherit; }
.key-concept { background:var(--accent); color:#fff; padding:16px 20px; border-radius:var(--r); margin:10px 0; box-shadow:var(--shadow); }
.key-concept h4 { color:#CDE7E2 !important; margin:0 0 6px 0; font-size:0.78rem !important; text-transform:uppercase; letter-spacing:1.2px; }
.real-world-box { background:var(--dark); color:#ECEAE4; padding:16px 20px; border-radius:var(--r); border-left:4px solid #8F86B8; margin:10px 0; }
.real-world-box strong { color:#CBC5E6; }

/* ── Threat severity + answers + scores ───────────────────────────────────────────── */
.threat-critical { background:var(--bad); color:#fff; padding:14px 16px; border-radius:var(--r); margin:8px 0; }
.threat-high { background:var(--bad-soft); padding:14px 16px; border-radius:var(--r); border:1px solid var(--bad-line); border-left:4px solid var(--bad); margin:8px 0; }
.threat-medium { background:var(--warn-soft); padding:14px 16px; border-radius:var(--r); border:1px solid var(--warn-line); border-left:4px solid var(--warn); margin:8px 0; }
.threat-low { background:var(--ok-soft); padding:14px 16px; border-radius:var(--r); border:1px solid var(--ok-line); border-left:4px solid var(--ok); margin:8px 0; }
.correct-answer { background:var(--ok-soft); padding:14px 16px; border-radius:var(--r); border:1px solid var(--ok-line); border-left:4px solid var(--ok); margin:8px 0; }
.incorrect-answer { background:var(--bad-soft); padding:14px 16px; border-radius:var(--r); border:1px solid var(--bad-line); border-left:4px solid var(--bad); margin:8px 0; }
.partial-answer { background:var(--warn-soft); padding:14px 16px; border-radius:var(--r); border:1px solid var(--warn-line); border-left:4px solid var(--warn); margin:8px 0; }
.score-excellent, .score-good, .score-fair, .score-poor { color:#fff; padding:22px; border-radius:var(--r-lg); text-align:center; font-size:1.25rem; font-weight:650; letter-spacing:-0.01em; box-shadow:var(--shadow); }
.score-excellent { background:var(--ok); }
.score-good { background:#5E8A47; }
.score-fair { background:var(--warn); }
.score-poor { background:var(--bad); }
.mastery-badge { background:var(--dark); color:#F1E7C8; padding:14px 22px; border-radius:var(--r-lg); text-align:center; font-weight:650; font-size:1.05rem; margin:10px 0; border:1px solid #3A4541; }

/* ── Badges + chips ───────────────────────────────────────────────────────────────── */
.badge-completed, .badge-locked, .badge-available { padding:3px 12px; border-radius:999px; font-size:.78rem; font-weight:600; display:inline-block; }
.badge-completed { background:var(--ok-soft); color:var(--ok); border:1px solid var(--ok-line); }
.badge-locked { background:var(--sunken); color:var(--muted); border:1px solid var(--line); }
.badge-available { background:var(--accent-soft); color:var(--accent); border:1px solid var(--accent-line); }
.step-active { background:var(--accent); color:#fff; padding:8px 12px; border-radius:10px; font-weight:650; font-size:.82rem; text-align:center; }
.step-done { background:var(--ok-soft); color:var(--ok); padding:8px 12px; border-radius:10px; font-weight:600; font-size:.82rem; text-align:center; border:1px solid var(--ok-line); }
.step-todo { background:var(--sunken); color:var(--muted); padding:8px 12px; border-radius:10px; font-size:.82rem; text-align:center; border:1px solid var(--line); }

/* ── Hero (home) ──────────────────────────────────────────────────────────────────── */
.hero { background:var(--surface); border:1px solid var(--line); border-radius:20px; padding:38px 40px; margin-bottom:26px; box-shadow:var(--shadow); position:relative; overflow:hidden; }
.hero:before { content:""; position:absolute; right:-70px; top:-70px; width:260px; height:260px; border-radius:50%; background:var(--accent-soft); opacity:.9; }
.hero:after { content:""; position:absolute; right:60px; bottom:-90px; width:160px; height:160px; border-radius:50%; background:var(--sunken); opacity:.9; }
.hero > * { position:relative; z-index:1; }
.hero .eyebrow { display:inline-block; font-size:.74rem; font-weight:650; letter-spacing:1.4px; text-transform:uppercase; color:var(--accent); background:var(--accent-soft); border:1px solid var(--accent-line); padding:4px 12px; border-radius:999px; margin-bottom:14px; }
.hero h1 { margin:0 0 10px 0 !important; font-size:2.35rem !important; max-width:760px; }
.hero p { color:var(--ink-2); font-size:1.08rem; margin:0 0 20px 0; max-width:700px; }
.chips { display:flex; gap:8px; flex-wrap:wrap; }
.chip { background:var(--surface-2); color:var(--ink-2); border:1px solid var(--line); padding:6px 14px; border-radius:999px; font-size:.82rem; font-weight:500; }

/* ── Stage tracker ────────────────────────────────────────────────────────────────── */
.stepper { display:flex; align-items:flex-start; padding:6px 2px 2px; overflow-x:auto; }
.stg { display:flex; flex-direction:column; align-items:center; gap:6px; min-width:78px; }
.stg-dot { width:30px; height:30px; border-radius:50%; display:flex; align-items:center; justify-content:center; font-weight:600; font-size:12px; border:1.5px solid var(--line-2); background:var(--surface); color:var(--muted); }
.stg-label { font-size:11px; color:var(--muted); text-align:center; font-weight:500; line-height:1.25; }
.stg-done .stg-dot { background:var(--accent-soft); border-color:var(--accent-line); color:var(--accent); }
.stg-done .stg-label { color:var(--ink-2); }
.stg-active .stg-dot { background:var(--accent); border-color:var(--accent); color:#fff; box-shadow:0 0 0 4px var(--accent-soft); }
.stg-active .stg-label { color:var(--ink); font-weight:650; }
.stg-line { flex:1; height:2px; background:var(--line); margin-top:15px; min-width:10px; }

/* ── Sidebar ──────────────────────────────────────────────────────────────────────── */
[data-testid="stSidebar"] { background:var(--sunken); border-right:1px solid var(--line); }
[data-testid="stSidebar"] .stButton>button { background:var(--surface); color:var(--ink); border:1px solid var(--line-2); margin:2px 0; }
[data-testid="stSidebar"] .stButton>button:hover { border-color:var(--accent); color:var(--accent-ink); }
[data-testid="stSidebar"] hr { border-color:var(--line); }
[data-testid="stSidebar"] h3 { font-size:0.8rem !important; text-transform:uppercase; letter-spacing:1.2px; color:var(--muted) !important; font-weight:650 !important; margin-top:.4rem; }
.brand { padding:6px 2px 10px 2px; }
.brand .logo { display:inline-flex; align-items:center; justify-content:center; width:38px; height:38px; border-radius:11px; background:var(--accent); color:#fff; font-size:1.15rem; margin-bottom:10px; }
.brand .name { font-weight:700; font-size:1.05rem; letter-spacing:-0.02em; color:var(--ink); }
.brand .tag { font-size:.74rem; color:var(--muted); margin-top:3px; line-height:1.45; }
.now-card { background:var(--surface); border:1px solid var(--line); border-left:4px solid var(--accent); border-radius:var(--r); padding:10px 14px; margin:8px 0; }
.now-eyebrow { font-size:.66rem; text-transform:uppercase; letter-spacing:1.4px; color:var(--accent); font-weight:650; margin-bottom:3px; }
.now-title { font-weight:650; font-size:.92rem; color:var(--ink); }
.now-meta { font-size:.78rem; color:var(--muted); margin-top:2px; }
.score-line { margin:6px 0 2px 0; font-size:.82rem; color:var(--ink-2); }
.score-line strong { color:var(--ink); }

/* ── Motion + scrollbars ──────────────────────────────────────────────────────────── */
@media (prefers-reduced-motion: reduce) { * { transition:none !important; animation:none !important; } }
::-webkit-scrollbar { height:8px; width:8px; }
::-webkit-scrollbar-thumb { background:var(--line-2); border-radius:8px; }
::-webkit-scrollbar-track { background:transparent; }
@media (max-width: 760px) { .hero { padding:26px 22px; } .hero h1 { font-size:1.7rem !important; } .block-container { padding-left:1rem; padding-right:1rem; } }
</style>""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# SESSION STATE
# ─────────────────────────────────────────────────────────────────────────────
def init_session_state():
    defaults = {
        'selected_workshop': None,
        'completed_workshops': set(),
        'unlocked_workshops': {'1'},
        'current_step': 1,
        'threats': [],
        'user_answers': [],
        'total_score': 0,
        'max_score': 0,
        'diagram_generated': None,
        'detailed_diagram_generated': None,
        'show_unlock_form': {},
        'annotations': {},          # {workshop_id: [label dicts]}
        'annot_nonce': 0,
        'scope_models': {},         # {workshop_id: scope / assumptions / exclusions}
        'open_questions': {},       # {workshop_id: {questions, accepted}}
        'review_plans': {},         # {workshop_id: review cadence + triggers}
        'stride_map': {},           # {workshop_id: {element key: [STRIDE letters]}}
        'boundary_checked': {},     # {workshop_id: True once the trust-boundary exercise was submitted}
        # NEW: Zone of Trust labelling state per workshop
        'zone_labels': {},          # {component: criticality_label}
        'zone_scores': {},          # {component: 0-9 score}
        'zone_labelling_done': False,
        # NEW: STRIDE rules exercise state
        'stride_rules_answers': {},
        'stride_rules_submitted': False,
        # NEW: OWASP mapping exercise state
        'owasp_mapping_answers': {},
        'owasp_mapping_submitted': False,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

init_session_state()


def start_workshop(ws_id):
    """Single place that resets all per-workshop state (was duplicated, with a key typo)."""
    st.session_state.selected_workshop = ws_id
    st.session_state.current_step = 1
    st.session_state.threats = []
    st.session_state.user_answers = []
    st.session_state.total_score = 0
    st.session_state.max_score = 0
    st.session_state.zone_labels = {}
    st.session_state.zone_scores = {}
    st.session_state.zone_labelling_done = False
    st.session_state.stride_rules_answers = {}
    st.session_state.stride_rules_submitted = False
    st.session_state.owasp_mapping_answers = {}
    st.session_state.owasp_mapping_submitted = False
    st.session_state.annotations[ws_id] = []
    st.session_state.scope_models[ws_id] = {}
    st.session_state.open_questions[ws_id] = {}
    st.session_state.review_plans[ws_id] = {}
    st.session_state.stride_map[ws_id] = {}
    st.session_state.boundary_checked[ws_id] = False
    for k in [k for k in st.session_state.keys() if str(k).startswith(("w_", "_seed_", "ed_"))]:
        del st.session_state[k]


# ─────────────────────────────────────────────────────────────────────────────
# OWASP ↔ STRIDE MAPPING  (from Infosec walkthrough)
# ─────────────────────────────────────────────────────────────────────────────
OWASP_STRIDE_MAP = {
    "Spoofing": {
        "owasp": ["A07:2021 – Identification and Authentication Failures",
                  "A02:2021 – Cryptographic Failures"],
        "controls": [
            "Implement multi-factor authentication (MFA) to prevent credential stuffing and brute force",
            "Use server-side, secure session manager generating random session IDs with high entropy",
            "Invalidate sessions after logout, idle and absolute timeouts",
            "Enforce strong password policies aligned with NIST 800-63B"
        ],
        "owasp_detail": "Broken Authentication maps directly to Spoofing – an attacker impersonates a legitimate user by exploiting weak authentication.",
    },
    "Tampering": {
        "owasp": ["A03:2021 – Injection", "A08:2021 – Software and Data Integrity Failures"],
        "controls": [
            "Use parameterized queries / prepared statements (never concatenate user input into SQL)",
            "Use positive (allowlist) server-side input validation",
            "Implement digital signatures / HMAC on serialized objects to prevent hostile data modification",
            "Use ORM frameworks that abstract safe SQL generation"
        ],
        "owasp_detail": "Injection (SQL, command, LDAP) and Insecure Deserialization both enable attackers to modify data or behaviour – the hallmark of Tampering.",
    },
    "Repudiation": {
        "owasp": ["A09:2021 – Security Logging and Monitoring Failures"],
        "controls": [
            "Ensure logs are generated in a format consumable by centralized log management (SIEM)",
            "Ensure high-value transactions have an audit trail with integrity controls (append-only DB tables)",
            "Log authentication events, data modifications, and access control failures",
            "Use write-once / immutable log storage to prevent attacker log tampering"
        ],
        "owasp_detail": "Insufficient logging means an attacker can act without a trace – enabling repudiation of their actions. OWASP ranks this #9 because most breaches exploit the absence of monitoring.",
    },
    "Information Disclosure": {
        "owasp": ["A02:2021 – Cryptographic Failures",
                  "A05:2021 – Security Misconfiguration"],
        "controls": [
            "Encrypt all data in transit with TLS 1.3 + HSTS (HTTP Strict Transport Security)",
            "Store passwords using strong adaptive hashing (Argon2, bcrypt, PBKDF2)",
            "Disable verbose error messages in production (use generic user-facing messages)",
            "Apply least-privilege access to secrets; use a secrets manager (AWS Secrets Manager, Vault)"
        ],
        "owasp_detail": "Cryptographic Failures (formerly Sensitive Data Exposure) occurs when data is transmitted or stored without adequate encryption. Security Misconfiguration (verbose errors, open S3 buckets) leaks information to attackers.",
    },
    "Denial of Service": {
        "owasp": ["A05:2021 – Security Misconfiguration",
                  "A04:2021 – Insecure Design"],
        "controls": [
            "Implement segmented application architecture with effective separation between components",
            "Apply rate limiting per user/IP at the API gateway layer",
            "Use circuit breaker pattern to prevent cascade failures",
            "Enable auto-scaling and deploy WAF with rate-based rules (AWS WAF / Cloudflare)"
        ],
        "owasp_detail": "Security Misconfiguration (no rate limits, open network) and Insecure Design (unbounded queries, no timeouts) create conditions for DoS. The attacker exploits a lack of resource controls.",
    },
    "Elevation of Privilege": {
        "owasp": ["A01:2021 – Broken Access Control",
                  "A04:2021 – Insecure Design"],
        "controls": [
            "Deny access by default – explicitly grant each permission",
            "Implement access control mechanisms once and re-use throughout the application",
            "Minimize CORS usage; validate ownership on every API object access",
            "Use Role-Based Access Control (RBAC) and validate on every request server-side"
        ],
        "owasp_detail": "Broken Access Control is OWASP #1 – it covers privilege escalation (user→admin), BOLA (horizontal escalation), and function-level authorization bypass. All are Elevation of Privilege.",
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# CRITICALITY ZONE DEFINITIONS  (from Infosec walkthrough)
# ─────────────────────────────────────────────────────────────────────────────
CRITICALITY_ZONES = {
    "Not in Control of System": {
        "range": "0",
        "score": 0,
        "color": "#F6F5F4",
        "border": "#7F786B",
        "description": "External actors (users, third-party services) – no trust assumed",
        "examples": "End users, external APIs, third-party payment providers",
        "stride_applicability": "Source of Spoofing, DoS, and Repudiation threats"
    },
    "Minimal Trust": {
        "range": "1–2",
        "score": 1,
        "color": "#EFEFEE",
        "border": "#418544",
        "description": "Entry points with basic authentication – low criticality",
        "examples": "Web frontend, mobile app, CDN edge",
        "stride_applicability": "Tampering and Information Disclosure via unvalidated input/output"
    },
    "Standard Application": {
        "range": "3–4",
        "score": 3,
        "color": "#F9F4CA",
        "border": "#E4A33A",
        "description": "Application-layer services with authentication enforced",
        "examples": "API backend, microservices, application servers",
        "stride_applicability": "All STRIDE categories – most complex threat surface"
    },
    "Elevated Trust": {
        "range": "5–6",
        "score": 5,
        "color": "#F7DEBA",
        "border": "#CF5817",
        "description": "Services with privileged access or sensitive business logic",
        "examples": "Payment services, auth services, admin APIs",
        "stride_applicability": "Elevation of Privilege, Tampering, and Information Disclosure are highest risk"
    },
    "Critical": {
        "range": "7–8",
        "score": 7,
        "color": "#FAD2D6",
        "border": "#C33F3F",
        "description": "Data stores and systems containing sensitive/regulated data",
        "examples": "Databases, data warehouses, encryption key stores",
        "stride_applicability": "Information Disclosure and Tampering are existential risks"
    },
    "Maximum Security": {
        "range": "9",
        "score": 9,
        "color": "#A82B2B",
        "border": "#6F0C0C",
        "description": "Safety-critical or life-critical systems",
        "examples": "Medical device data, safety alert systems, nuclear control",
        "stride_applicability": "All STRIDE threats carry life-safety or business-ending consequences"
    }
}

# STRIDE RULES based on zone relationships (from Infosec walkthrough methodology)
STRIDE_ZONE_RULES = {
    "flows": {
        "Tampering": {
            "rule": "Data flow from a LESS critical zone to a MORE critical zone",
            "rationale": "An attacker at lower trust can inject malicious data into a higher-trust system (e.g., SQL injection from web input to database)",
            "direction": "less → more",
            "example": "Web Frontend (zone 1) → API Backend (zone 3): Attacker injects XSS payload"
        },
        "Information Disclosure": {
            "rule": "Data flow from a MORE critical zone to a LESS critical zone",
            "rationale": "Sensitive data flowing outward may be captured by a less-trusted component (e.g., database results returned to browser)",
            "direction": "more → less",
            "example": "Database (zone 7) → API Backend (zone 3): Attacker reads sensitive data in verbose API response"
        },
        "Denial of Service": {
            "rule": "Any flow from a 'Not in Control' (zone 0) node to any other node",
            "rationale": "External actors with no trust can flood any entry point they can reach",
            "direction": "zone 0 → any",
            "example": "User/Internet (zone 0) → API Backend (zone 3): Botnet floods login endpoint"
        }
    },
    "nodes": {
        "Spoofing": {
            "rule": "Any node that a 'Not in Control' (zone 0) entity can connect to",
            "rationale": "If an external actor can reach a node, they may impersonate a legitimate user or system",
            "applies_to": "Nodes connected to zone-0 entities",
            "example": "Login endpoint reached by Users: Attacker uses stolen credentials or brute force"
        },
        "Repudiation": {
            "rule": "Any node where BOTH Spoofing AND Tampering are applicable",
            "rationale": "If identity can be spoofed and data can be tampered, an attacker can perform actions that cannot be traced back to them",
            "applies_to": "Nodes at spoofing + tampering intersection",
            "example": "API Backend: Actions can be performed as a fake identity with modified data, then denied"
        },
        "Denial of Service": {
            "rule": "Any node that a 'Not in Control' (zone 0) entity connects to",
            "rationale": "External entities can exhaust resources of any reachable node",
            "applies_to": "All nodes reachable from zone-0",
            "example": "API Backend: External user floods requests until service crashes"
        },
        "Elevation of Privilege": {
            "rule": "Any node connected to a less-critical (lower zone number) node",
            "rationale": "If a less-trusted component can reach this node, an attacker who compromises the lower zone may gain the privileges of the higher zone",
            "applies_to": "Higher-zone nodes reachable from lower-zone nodes",
            "example": "Admin API (zone 5) reachable from API Backend (zone 3): Attacker escalates from regular user to admin"
        }
    }
}


# ─────────────────────────────────────────────────────────────────────────────
# COMPLETE THREAT DATABASE
# ─────────────────────────────────────────────────────────────────────────────
PREDEFINED_THREATS = {
    "1": [
        {"id": "T-001", "stride": "Spoofing", "component": "Web Frontend → API Backend",
         "threat": "Session hijacking via XSS allowing attacker to impersonate legitimate user",
         "likelihood": "Medium", "impact": "High",
         "correct_mitigations": ["HttpOnly and Secure flags on cookies",
                                  "Content Security Policy (CSP) headers",
                                  "Input sanitization with DOMPurify",
                                  "XSS prevention through output encoding"],
         "incorrect_mitigations": ["Increase password complexity", "Add rate limiting", "Enable 2FA"],
         "explanation": "XSS attacks allow stealing session cookies. HttpOnly prevents JavaScript from accessing cookies, CSP restricts allowed script sources, and input sanitization prevents malicious script injection.",
         "compliance": "OWASP Top 10 A03:2021 (Injection), OWASP ASVS V5.3.3, PCI-DSS 6.5.7",
         "points": 10,
         "why_this_risk": "Medium likelihood because XSS is common (found in 40% of apps). High impact because session hijacking gives full account access.",
         "why_these_controls": "HttpOnly blocks cookie theft via JavaScript. CSP prevents unauthorized scripts from running. DOMPurify sanitizes user input before rendering.",
         "real_world": "British Airways fined £20M for breach involving XSS (2019). Magecart attacks use XSS to steal payment data.",
         "zone_from": "Minimal Trust", "zone_to": "Standard Application",
         "stride_rule_applied": "Tampering/Spoofing: Less-critical zone (1) to more-critical zone (3) + external entity (zone 0) connection",
         "owasp_categories": ["A03:2021 – Injection", "A07:2021 – Identification and Authentication Failures"]},

        {"id": "T-002", "stride": "Tampering", "component": "API Backend → Database",
         "threat": "SQL injection allowing modification of product prices or customer data",
         "likelihood": "Medium", "impact": "Critical",
         "correct_mitigations": ["Parameterized queries/Prepared statements",
                                  "Use ORM (Sequelize, TypeORM)",
                                  "Input validation with allowlisting",
                                  "Least privilege database user"],
         "incorrect_mitigations": ["Encrypt database connections", "Add logging", "Use strong passwords"],
         "explanation": "SQL injection exploits unsanitized user input in SQL queries. Parameterized queries separate SQL code from data, preventing injection.",
         "compliance": "OWASP Top 10 A03:2021, PCI-DSS 6.5.1, CWE-89",
         "points": 10,
         "why_this_risk": "Medium likelihood - still found in 25% of applications. Critical impact - can modify/delete ALL data including prices and customer records.",
         "why_these_controls": "Parameterized queries treat user input as data only, never as executable SQL. ORMs abstract SQL generation safely.",
         "real_world": "Target breach (2013) started with SQL injection. 40M credit cards stolen, $18M settlement.",
         "zone_from": "Standard Application", "zone_to": "Critical",
         "stride_rule_applied": "Tampering: Data flow from less-critical (zone 3 API) to more-critical (zone 7 DB) – attacker injects SQL via lower zone",
         "owasp_categories": ["A03:2021 – Injection", "A08:2021 – Software and Data Integrity Failures"]},

        {"id": "T-003", "stride": "Information Disclosure", "component": "Database",
         "threat": "Unencrypted customer PII in database exposed through backup theft or breach",
         "likelihood": "Low", "impact": "Critical",
         "correct_mitigations": ["AES-256 encryption at rest", "AWS RDS encryption enabled",
                                  "Encrypt database backups", "AWS KMS for key management"],
         "incorrect_mitigations": ["Add firewall rules", "Increase password strength", "Add monitoring"],
         "explanation": "Unencrypted data at rest can be exposed if storage media is stolen or accessed. Encryption ensures data remains protected even if physical security fails.",
         "compliance": "GDPR Article 32, PCI-DSS 3.4, HIPAA 164.312(a)(2)(iv)",
         "points": 10,
         "why_this_risk": "Low likelihood - requires physical access or major breach. Critical impact - GDPR fines up to 4% of global revenue, massive reputation damage.",
         "why_these_controls": "Encryption at rest is baseline compliance requirement. Even if database stolen, data is unusable without keys.",
         "real_world": "Equifax breach exposed 147M people. Encryption would have limited damage. €50M GDPR fine.",
         "zone_from": "Critical", "zone_to": "Not in Control of System",
         "stride_rule_applied": "Information Disclosure: Data in critical zone (7) – direct node risk when zone boundary collapses through misconfig",
         "owasp_categories": ["A02:2021 – Cryptographic Failures", "A05:2021 – Security Misconfiguration"]},

        {"id": "T-004", "stride": "Denial of Service", "component": "API Backend",
         "threat": "API flooding attack exhausting server resources causing service unavailability",
         "likelihood": "High", "impact": "Medium",
         "correct_mitigations": ["Rate limiting per user/IP", "AWS WAF with rate-based rules",
                                  "Auto-scaling for ECS tasks", "AWS Shield Standard/Advanced"],
         "incorrect_mitigations": ["Add more memory", "Enable logging", "Use encryption"],
         "explanation": "DoS attacks overwhelm resources. Rate limiting restricts requests per user, auto-scaling adds capacity dynamically, WAF filters malicious traffic.",
         "compliance": "OWASP Top 10 A05:2021 (Security Misconfiguration)",
         "points": 10,
         "why_this_risk": "High likelihood - DDoS attacks cheap and easy with botnets. Medium impact - revenue loss and customer frustration but no data breach.",
         "why_these_controls": "Rate limiting blocks request floods. Auto-scaling handles legitimate traffic spikes. WAF blocks attack patterns.",
         "real_world": "GitHub survived 1.35 Tbps DDoS (2018) using auto-scaling and traffic filtering. Dyn DNS attack took down Twitter, Netflix (2016).",
         "zone_from": "Not in Control of System", "zone_to": "Standard Application",
         "stride_rule_applied": "Denial of Service: Zone-0 (Users) connects to API Backend – external entity can exhaust any reachable node",
         "owasp_categories": ["A05:2021 – Security Misconfiguration", "A04:2021 – Insecure Design"]},

        {"id": "T-005", "stride": "Elevation of Privilege", "component": "API Backend",
         "threat": "Broken access control allowing regular user to access admin endpoints",
         "likelihood": "Medium", "impact": "High",
         "correct_mitigations": ["Role-Based Access Control (RBAC)",
                                  "Validate permissions on every request",
                                  "Principle of least privilege",
                                  "Deny by default access policy"],
         "incorrect_mitigations": ["Encrypt API traffic", "Add logging", "Use strong authentication"],
         "explanation": "Authentication confirms identity, but authorization determines access rights. RBAC ensures users only access resources appropriate for their role.",
         "compliance": "OWASP Top 10 A01:2021 (Broken Access Control), PCI-DSS 7.1, NIST 800-53 AC-2",
         "points": 10,
         "why_this_risk": "Medium likelihood - common developer oversight. High impact - admin access = full system control, data modification.",
         "why_these_controls": "Check authorization on EVERY request, not just authentication. Deny by default means explicitly grant each permission.",
         "real_world": "Instagram API bug (2020) let users access admin endpoints. Peloton API allowed accessing any user's data (2021).",
         "zone_from": "Minimal Trust", "zone_to": "Standard Application",
         "stride_rule_applied": "Elevation of Privilege (Node rule): API Backend (zone 3) is connected to a lower-zone node (Web Frontend zone 1). An attacker who compromises the lower zone (or forges requests appearing to come from it) can attempt to gain the privileges of the higher zone – e.g. calling admin endpoints that only the API backend should control.",
         "owasp_categories": ["A01:2021 – Broken Access Control"]},

        {"id": "T-006", "stride": "Repudiation", "component": "API Backend",
         "threat": "Insufficient logging allows attackers to cover tracks or users to deny actions",
         "likelihood": "Medium", "impact": "Medium",
         "correct_mitigations": ["Comprehensive audit logging",
                                  "Log authentication events",
                                  "Log all data modifications",
                                  "Centralized logging (CloudWatch)",
                                  "Write-once log storage"],
         "incorrect_mitigations": ["Add encryption", "Enable 2FA", "Use firewalls"],
         "explanation": "Non-repudiation requires proof of actions. Comprehensive audit logs create immutable record of who did what and when.",
         "compliance": "PCI-DSS 10 (all requirements), SOC 2 CC7.2, HIPAA 164.312(b)",
         "points": 10,
         "why_this_risk": "Medium/medium - can't investigate incidents without logs. Average time to detect breach: 207 days without proper logging.",
         "why_these_controls": "Audit logs record WHO (user), WHAT (action), WHEN (timestamp), WHERE (location). Write-once storage prevents log tampering.",
         "real_world": "Many breaches undetected for months due to no logging. GDPR requires logging for breach notification.",
         "zone_from": "Standard Application", "zone_to": "Standard Application",
         "stride_rule_applied": "Repudiation (Node rule): API Backend (zone 3) is reachable from Zone-0 (Spoofing applies) AND receives data from less-critical zones (Tampering applies). When BOTH Spoofing AND Tampering apply to the same node, Repudiation applies – an attacker can act as a fake identity with modified data, leaving no trace.",
         "owasp_categories": ["A09:2021 – Security Logging and Monitoring Failures"]},

        {"id": "T-007", "stride": "Tampering", "component": "Customer → Web Frontend",
         "threat": "Man-in-the-middle attack intercepting and modifying data in transit",
         "likelihood": "Low", "impact": "High",
         "correct_mitigations": ["TLS 1.3 for all connections", "HSTS headers",
                                  "Certificate pinning in mobile apps",
                                  "Enforce HTTPS with redirects"],
         "incorrect_mitigations": ["Add database encryption", "Enable logging", "Use strong passwords"],
         "explanation": "MITM attacks intercept unencrypted communications. TLS encrypts data in transit, HSTS prevents protocol downgrade attacks.",
         "compliance": "PCI-DSS 4.1, OWASP ASVS V9.1.1",
         "points": 10,
         "why_this_risk": "Low likelihood - HTTPS now default. High impact - can steal credentials, payment data, session tokens.",
         "why_these_controls": "TLS 1.3 encrypts all traffic. HSTS forces browsers to always use HTTPS, preventing downgrade to HTTP.",
         "real_world": "Public WiFi MITM attacks common. Firesheep tool (2010) showed how easy cookie theft is on unencrypted WiFi.",
         "zone_from": "Not in Control of System", "zone_to": "Minimal Trust",
         "stride_rule_applied": "Tampering: Flow from zone-0 (Customer) to zone-1 (Frontend) – the least-trusted boundary where MITM attacks intercept data",
         "owasp_categories": ["A02:2021 – Cryptographic Failures", "A08:2021 – Software and Data Integrity Failures"]},

        {"id": "T-008", "stride": "Information Disclosure", "component": "API Backend",
         "threat": "Verbose error messages exposing stack traces and internal system paths to attackers",
         "likelihood": "High", "impact": "Low",
         "correct_mitigations": ["Generic error messages for users",
                                  "Log detailed errors server-side only",
                                  "Disable debug mode in production",
                                  "Custom error pages"],
         "incorrect_mitigations": ["Encrypt error messages", "Add authentication", "Use rate limiting"],
         "explanation": "Detailed errors reveal system internals to attackers. Production systems show generic errors to users while logging details server-side.",
         "compliance": "OWASP Top 10 A05:2021, CWE-209 (Information Exposure Through Error Message)",
         "points": 10,
         "why_this_risk": "High likelihood - very common mistake, often left in production. Low impact - aids reconnaissance but doesn't directly breach data.",
         "why_these_controls": "Generic user-facing errors hide internals. Detailed server-side logs help debugging without exposing information.",
         "real_world": "Stack traces fingerprint frameworks and versions, helping attackers find known exploits.",
         "zone_from": "Standard Application", "zone_to": "Not in Control of System",
         "stride_rule_applied": "Information Disclosure: Data flows from higher-trust API (zone 3) back to zone-0 User – verbose errors leak internal architecture",
         "owasp_categories": ["A05:2021 – Security Misconfiguration", "A02:2021 – Cryptographic Failures"]},

        {"id": "T-009", "stride": "Spoofing", "component": "Customer",
         "threat": "Weak password policy allowing brute force attacks to compromise user accounts",
         "likelihood": "High", "impact": "Medium",
         "correct_mitigations": ["Strong password requirements (12+ chars, complexity)",
                                  "Multi-Factor Authentication (MFA)",
                                  "Account lockout after failed attempts",
                                  "CAPTCHA on login",
                                  "Password breach detection"],
         "incorrect_mitigations": ["Encrypt passwords in database", "Add logging", "Use HTTPS"],
         "explanation": "Weak passwords easily guessed. Strong password policies combined with MFA and account lockout make brute force impractical.",
         "compliance": "OWASP ASVS V2.1.1, PCI-DSS 8.2.3, NIST 800-63B",
         "points": 10,
         "why_this_risk": "High likelihood - 80% of breaches involve weak/stolen passwords. Medium impact - one account compromised, not entire database.",
         "why_these_controls": "Long passwords resist brute force (12 chars = 10^21 combinations). MFA requires second factor even if password stolen.",
         "real_world": "Credential stuffing tries leaked passwords across sites. 15B credentials available on dark web. MFA blocks 99.9% of attacks.",
         "zone_from": "Not in Control of System", "zone_to": "Minimal Trust",
         "stride_rule_applied": "Spoofing: Zone-0 (Customer) connects to login system – external entity impersonates legitimate user through credential attack",
         "owasp_categories": ["A07:2021 – Identification and Authentication Failures"]},

        {"id": "T-010", "stride": "Elevation of Privilege", "component": "API Backend → S3 Storage",
         "threat": "Misconfigured S3 bucket with public access allowing unauthorized uploads or data exposure",
         "likelihood": "Medium", "impact": "High",
         "correct_mitigations": ["S3 Block Public Access enabled",
                                  "Bucket policies with least privilege",
                                  "IAM roles for API access (not keys)",
                                  "S3 access logging enabled",
                                  "Regular access audits"],
         "incorrect_mitigations": ["Encrypt S3 objects", "Add CloudWatch monitoring", "Use strong passwords"],
         "explanation": "Misconfigured S3 buckets common vulnerability. Block Public Access prevents accidental exposure, IAM roles provide granular control.",
         "compliance": "AWS Well-Architected Security Pillar, CIS AWS Foundations Benchmark 2.1.5",
         "points": 10,
         "why_this_risk": "Medium likelihood - easy to misconfigure. High impact - public data breach, regulatory fines.",
         "why_these_controls": "Block Public Access is global override preventing public access. IAM roles rotate credentials automatically.",
         "real_world": "Capital One breach (2019) exposed 100M customers via S3 misconfiguration. $80M fine.",
         "zone_from": "Standard Application", "zone_to": "Critical",
         "stride_rule_applied": "Elevation of Privilege: S3 (critical zone) reachable from lower-trust API – misconfiguration lets attacker gain storage-level access beyond their role",
         "owasp_categories": ["A01:2021 – Broken Access Control", "A05:2021 – Security Misconfiguration"]},

        {"id": "T-011", "stride": "Tampering", "component": "Web Frontend",
         "threat": "DOM-based XSS through client-side JavaScript manipulation of user input",
         "likelihood": "Medium", "impact": "Medium",
         "correct_mitigations": ["Use React's built-in XSS protection",
                                  "Avoid dangerouslySetInnerHTML",
                                  "DOMPurify for sanitization when needed",
                                  "Content Security Policy",
                                  "Validate all user inputs"],
         "incorrect_mitigations": ["Add server-side validation only", "Use HTTPS", "Enable database encryption"],
         "explanation": "DOM-based XSS occurs in browser. React escapes output by default, but developers must avoid unsafe patterns.",
         "compliance": "OWASP Top 10 A03:2021, CWE-79 (XSS)",
         "points": 10,
         "why_this_risk": "Medium likelihood - requires unsafe React patterns. Medium impact - session theft, defacement.",
         "why_these_controls": "React auto-escapes JSX expressions. dangerouslySetInnerHTML bypasses protection. CSP blocks unauthorized scripts.",
         "real_world": "DOM XSS harder to detect than reflected XSS. Modern frameworks help but developers can still create vulnerabilities.",
         "zone_from": "Not in Control of System", "zone_to": "Minimal Trust",
         "stride_rule_applied": "Tampering: Zone-0 user input enters zone-1 frontend – malicious script modifies DOM behavior",
         "owasp_categories": ["A03:2021 – Injection"]},

        {"id": "T-012", "stride": "Information Disclosure", "component": "API Backend → Stripe",
         "threat": "API keys hardcoded in frontend code exposing Stripe credentials in source",
         "likelihood": "High", "impact": "Critical",
         "correct_mitigations": ["Use Stripe publishable keys in frontend",
                                  "Store secret keys in AWS Secrets Manager",
                                  "Never commit keys to version control",
                                  "Rotate keys regularly",
                                  "Use environment variables"],
         "incorrect_mitigations": ["Encrypt keys in code", "Obfuscate JavaScript", "Add rate limiting"],
         "explanation": "Frontend code is visible to users. Use publishable keys for client-side, keep secret keys server-side in secure stores.",
         "compliance": "PCI-DSS 6.5.3 (Protect cryptographic keys), OWASP Top 10 A05:2021",
         "points": 10,
         "why_this_risk": "High likelihood - frontend code is PUBLIC. Critical impact - direct financial fraud, unauthorized charges.",
         "why_these_controls": "Publishable keys safe for frontend (restricted capabilities). Secret keys server-side only. Secrets Manager encrypts and rotates.",
         "real_world": "GitHub finds thousands of exposed API keys daily. Automated bots scan commits for secrets. $1M+ stolen via exposed Stripe keys.",
         "zone_from": "Standard Application", "zone_to": "Not in Control of System",
         "stride_rule_applied": "Information Disclosure: Secret credentials (high trust) leak into zone-0 visible frontend – any user can extract the key",
         "owasp_categories": ["A02:2021 – Cryptographic Failures", "A05:2021 – Security Misconfiguration"]},

        {"id": "T-013", "stride": "Denial of Service", "component": "Database",
         "threat": "Expensive database queries without pagination causing resource exhaustion",
         "likelihood": "Medium", "impact": "Medium",
         "correct_mitigations": ["Implement pagination (limit/offset)", "Query timeouts",
                                  "Database connection pooling",
                                  "Index frequently queried fields",
                                  "Query complexity analysis"],
         "incorrect_mitigations": ["Add more database storage", "Enable encryption", "Add logging"],
         "explanation": "Unbounded queries exhaust memory and CPU. Pagination limits result sets, timeouts prevent long-running queries.",
         "compliance": "OWASP API Security Top 10 API4:2023 (Unrestricted Resource Consumption)",
         "points": 10,
         "why_this_risk": "Medium/medium - legitimate users can trigger expensive queries. Impacts all users when DB slows.",
         "why_these_controls": "Pagination limits data returned per request. Timeouts kill runaway queries. Indexes speed up lookups.",
         "real_world": "Unoptimized queries crash databases during traffic spikes. Black Friday sales bring down e-commerce sites.",
         "zone_from": "Standard Application", "zone_to": "Critical",
         "stride_rule_applied": "Denial of Service: API (zone 3) sends requests to DB (zone 7) – unbounded queries exhaust critical data store resources",
         "owasp_categories": ["A04:2021 – Insecure Design", "A05:2021 – Security Misconfiguration"]},

        {"id": "T-014", "stride": "Spoofing", "component": "API Backend → SendGrid",
         "threat": "Email spoofing allowing attackers to send phishing emails appearing from legitimate domain",
         "likelihood": "Medium", "impact": "Medium",
         "correct_mitigations": ["SPF records configured", "DKIM signing enabled",
                                  "DMARC policy enforced (p=reject)",
                                  "Verify SendGrid API key security",
                                  "Monitor email sending patterns"],
         "incorrect_mitigations": ["Encrypt email content", "Add rate limiting", "Use strong passwords"],
         "explanation": "Email authentication (SPF, DKIM, DMARC) proves emails originate from authorized servers, preventing domain spoofing.",
         "compliance": "DMARC RFC 7489, Anti-Phishing Best Practices",
         "points": 10,
         "why_this_risk": "Medium/medium - easy to spoof emails. Brand damage from phishing, customer trust loss.",
         "why_these_controls": "SPF lists authorized mail servers. DKIM cryptographically signs emails. DMARC tells receivers what to do with failures.",
         "real_world": "Business Email Compromise (BEC) scams cost $2.4B in 2021 (FBI). Email spoofing enables phishing attacks.",
         "zone_from": "Standard Application", "zone_to": "Not in Control of System",
         "stride_rule_applied": "Spoofing: Email flows out to zone-0 recipients – attacker impersonates your domain to attack your users",
         "owasp_categories": ["A07:2021 – Identification and Authentication Failures"]},

        {"id": "T-015", "stride": "Tampering", "component": "API Backend",
         "threat": "Mass assignment vulnerability allowing users to modify unintended database fields",
         "likelihood": "Medium", "impact": "High",
         "correct_mitigations": ["Explicitly define allowed fields (allowlist)",
                                  "Use DTO (Data Transfer Objects)",
                                  "Validate input against schema",
                                  "Blacklist sensitive fields like isAdmin",
                                  "Use ORM's field protection"],
         "incorrect_mitigations": ["Encrypt the request", "Add authentication", "Enable logging"],
         "explanation": "Mass assignment occurs when APIs blindly accept all input fields. Explicitly defining allowed fields prevents modifying protected attributes.",
         "compliance": "OWASP API Security Top 10 API6:2023 (Mass Assignment), CWE-915",
         "points": 10,
         "why_this_risk": "Medium/high - can set isAdmin=true via POST. Trivial to exploit once discovered.",
         "why_these_controls": "Allow-lists define exactly which fields are updateable. Anything not on list is rejected.",
         "real_world": "GitHub mass assignment vulnerability (2012) let anyone gain admin access. Rails applications particularly vulnerable without strong_parameters.",
         "zone_from": "Not in Control of System", "zone_to": "Standard Application",
         "stride_rule_applied": "Tampering: Zone-0 user submits POST body to zone-3 API – unvalidated fields tamper with business-critical data",
         "owasp_categories": ["A03:2021 – Injection", "A08:2021 – Software and Data Integrity Failures"]}
    ],

    "2": [
        {"id": "T-101", "stride": "Information Disclosure", "component": "API Gateway → Payment Service",
         "threat": "BOLA (Broken Object Level Authorization) - accessing other users' data",
         "likelihood": "High", "impact": "Critical",
         "correct_mitigations": ["Object-level authorization on every API call",
                                  "Resource ownership checks",
                                  "Use UUIDs not sequential IDs",
                                  "Validate user owns resource"],
         "incorrect_mitigations": ["Add authentication", "Encrypt account ID", "Add rate limiting"],
         "explanation": "BOLA = broken object authorization. API returns data based only on object ID without verifying ownership.",
         "compliance": "OWASP API Security Top 10 - API1:2023",
         "points": 10,
         "why_this_risk": "High likelihood - trivial to exploit in banking apps. Critical impact - access to all customer financial data.",
         "why_these_controls": "Validate ownership on EVERY API call. Database query must include: WHERE id=? AND user_id=current_user",
         "real_world": "Peloton API (2021): Any user could access any other user's data by changing user ID. First American leaked 885M docs via BOLA (2019).",
         "zone_from": "Minimal Trust", "zone_to": "Elevated Trust",
         "stride_rule_applied": "Information Disclosure: API Gateway (zone 1) to Payment Service (zone 5) – data flows outward if ownership check missing",
         "owasp_categories": ["A01:2021 – Broken Access Control", "A02:2021 – Cryptographic Failures"]},

        {"id": "T-102", "stride": "Spoofing", "component": "User Service → Payment Service",
         "threat": "Service Impersonation - rogue service in service mesh",
         "likelihood": "Medium", "impact": "High",
         "correct_mitigations": ["Mutual TLS (mTLS) for service mesh",
                                  "Service identity verification",
                                  "Certificate-based authentication",
                                  "SPIFFE IDs for services"],
         "incorrect_mitigations": ["Use API keys only", "Add logging", "Network firewall"],
         "explanation": "Without mutual authentication, services accept requests from imposter. Attacker deploys rogue service pretending to be legitimate Payment Service.",
         "compliance": "NIST 800-204, Zero Trust Architecture",
         "points": 10,
         "why_this_risk": "Medium/high - needs cluster access but enables lateral movement and data theft.",
         "why_these_controls": "mTLS means both client and server present certificates. Service mesh (Istio, Linkerd) automatically handles mTLS.",
         "real_world": "Service mesh breaches prevented by mTLS. Without it, lateral movement trivial once attacker enters network.",
         "zone_from": "Elevated Trust", "zone_to": "Elevated Trust",
         "stride_rule_applied": "Spoofing: Both services are zone-5 (Elevated Trust) but service-to-service calls can be intercepted if mTLS not enforced",
         "owasp_categories": ["A07:2021 – Identification and Authentication Failures"]},

        {"id": "T-103", "stride": "Repudiation", "component": "Payment Service",
         "threat": "Insufficient Logging - can't trace distributed requests",
         "likelihood": "High", "impact": "Medium",
         "correct_mitigations": ["Distributed tracing (OpenTelemetry)",
                                  "Centralized logging (ELK/Splunk)",
                                  "Correlation IDs across services",
                                  "Structured JSON logging"],
         "incorrect_mitigations": ["Local file logging only", "No correlation IDs", "Minimal logging"],
         "explanation": "Microservices don't log service-to-service calls. When breach discovered, can't trace attacker's path through system.",
         "compliance": "PCI-DSS 10, SOC 2 CC7.2",
         "points": 10,
         "why_this_risk": "High/medium - very common oversight. Can't investigate incidents or prove compliance without proper logging.",
         "why_these_controls": "Distributed tracing creates trace showing request path across ALL services. Correlation ID propagates through every service call.",
         "real_world": "Average breach detection: 207 days without centralized logging. With proper logging: detected in hours.",
         "zone_from": "Elevated Trust", "zone_to": "Elevated Trust",
         "stride_rule_applied": "Repudiation: Payment Service has both Spoofing AND Tampering applicability – actions can be denied without distributed tracing",
         "owasp_categories": ["A09:2021 – Security Logging and Monitoring Failures"]},

        {"id": "T-104", "stride": "Denial of Service", "component": "API Gateway",
         "threat": "Rate Limiting Bypass - distributed botnet attack",
         "likelihood": "High", "impact": "High",
         "correct_mitigations": ["Global + Per-service rate limits",
                                  "Distributed rate limiting (Redis)",
                                  "Circuit breaker pattern",
                                  "WAF with geo-blocking"],
         "incorrect_mitigations": ["Per-IP limits only", "No distributed tracking", "Increase server capacity only"],
         "explanation": "Attacker uses distributed botnet with different IPs to bypass per-IP rate limits.",
         "compliance": "OWASP API Top 10 API4:2023 (Unrestricted Resource Consumption)",
         "points": 10,
         "why_this_risk": "High/high - DDoS attacks cheap and easy. Service outage = revenue loss for banking app.",
         "why_these_controls": "Redis-backed rate limiting shared across ALL gateway instances. Circuit breaker prevents cascade failures.",
         "real_world": "GitHub API: 5000 req/hour per user. CloudFlare: Global rate limiting prevented Tbps DDoS attacks.",
         "zone_from": "Not in Control of System", "zone_to": "Minimal Trust",
         "stride_rule_applied": "Denial of Service: Zone-0 Mobile App connects to API Gateway (zone 1) – external entities flood the entry point",
         "owasp_categories": ["A05:2021 – Security Misconfiguration", "A04:2021 – Insecure Design"]},

        {"id": "T-105", "stride": "Tampering", "component": "User Service → Payment Service",
         "threat": "Insecure Service-to-Service Communication - unencrypted inter-service traffic",
         "likelihood": "Medium", "impact": "Critical",
         "correct_mitigations": ["JWT validation on every service call",
                                  "Short token expiration (15min)",
                                  "Service mesh encryption (mTLS)",
                                  "TLS for all internal traffic"],
         "incorrect_mitigations": ["HTTP only for internal", "No token validation", "Long-lived tokens"],
         "explanation": "Services communicate over plain HTTP within cluster. Network sniffer captures credit card data in transit between services.",
         "compliance": "PCI-DSS 4.1, HIPAA 164.312(e)",
         "points": 10,
         "why_this_risk": "Medium/critical - needs network access but financial data exposed.",
         "why_these_controls": "Service mesh automatically encrypts all pod-to-pod traffic with mTLS. Network-level encryption layer prevents MITM.",
         "real_world": "Enterprises with mTLS prevented 100% of network-based lateral movement in red team exercises.",
         "zone_from": "Elevated Trust", "zone_to": "Elevated Trust",
         "stride_rule_applied": "Tampering: Inter-service flow within same zone – but without mTLS, a compromised node can modify messages in transit",
         "owasp_categories": ["A03:2021 – Injection", "A08:2021 – Software and Data Integrity Failures"]}
    ],

    "3": [
        {"id": "T-201", "stride": "Information Disclosure", "component": "Query Service → Data Warehouse",
         "threat": "Cross-Tenant Data Access - SQL missing tenant filter",
         "likelihood": "High", "impact": "Critical",
         "correct_mitigations": ["Row-Level Security (RLS) in PostgreSQL/Redshift",
                                  "Tenant context validation on every request",
                                  "WHERE tenant_id = :tenant_id in ALL queries",
                                  "Database-level enforcement"],
         "incorrect_mitigations": ["Application-level filtering only", "Trust tenant_id from request", "No RLS policies"],
         "explanation": "SQL query doesn't include tenant filter. Attacker from Tenant A crafts API request that returns Tenant B's data.",
         "compliance": "SOC 2 CC6.1 (Logical Access), ISO 27001 A.9.4.1",
         "points": 10,
         "why_this_risk": "High/critical - THE multi-tenant SaaS vulnerability. One query returns data from ALL tenants.",
         "why_these_controls": "PostgreSQL RLS policies enforce tenant_id filter on ALL queries automatically at database level.",
         "real_world": "GitHub Gist (2020): Cross-tenant data leak. SaaS platforms average 1-2 tenant isolation bugs per year.",
         "zone_from": "Standard Application", "zone_to": "Critical",
         "stride_rule_applied": "Information Disclosure: Query Service (zone 3) accesses Data Warehouse (zone 7) – missing tenant filter exposes all tenants' data from the critical zone",
         "owasp_categories": ["A01:2021 – Broken Access Control", "A05:2021 – Security Misconfiguration"]},

        {"id": "T-202", "stride": "Elevation of Privilege", "component": "API Gateway",
         "threat": "Tenant Isolation Bypass - modifying tenant context",
         "likelihood": "Medium", "impact": "Critical",
         "correct_mitigations": ["Tenant context from JWT ONLY (never request body)",
                                  "Middleware validation before all routes",
                                  "Admin namespace isolation (separate domain)",
                                  "Tenant existence and active status checks"],
         "incorrect_mitigations": ["Accept tenant_id from request body", "No middleware validation", "Same domain for admin and tenant APIs"],
         "explanation": "Attacker discovers admin endpoint /internal/all-tenants that bypasses tenant context.",
         "compliance": "SOC 2 CC6.1",
         "points": 10,
         "why_this_risk": "Medium/critical - needs to find vulnerability but impact is catastrophic cross-tenant access.",
         "why_these_controls": "EVERY API request includes X-Tenant-ID header extracted from JWT. Backend validates before processing.",
         "real_world": "Salesforce: Strict namespace isolation. Multi-tenant architecture review catches 90% of isolation bugs before production.",
         "zone_from": "Minimal Trust", "zone_to": "Standard Application",
         "stride_rule_applied": "Elevation of Privilege: API Gateway (zone 1-3) connected to shared services – user elevates from single-tenant to cross-tenant access",
         "owasp_categories": ["A01:2021 – Broken Access Control"]},

        {"id": "T-203", "stride": "Denial of Service", "component": "Query Service → Data Warehouse",
         "threat": "Noisy Neighbor Resource Exhaustion - one tenant impacts all",
         "likelihood": "High", "impact": "High",
         "correct_mitigations": ["Per-tenant resource quotas (CPU/memory/queries)",
                                  "Query timeout enforcement (30 seconds)",
                                  "Query complexity limits",
                                  "Priority queues for enterprise vs free tier"],
         "incorrect_mitigations": ["Unlimited resources per tenant", "No query timeouts", "Shared pool without limits"],
         "explanation": "Tenant A runs expensive analytics query consuming all database CPU. Tenant B's queries time out.",
         "compliance": "SLA commitments, Fair usage policies",
         "points": 10,
         "why_this_risk": "High/high - very common in shared infrastructure. Revenue loss when paying customers impacted.",
         "why_these_controls": "AWS Service Quotas or custom quota service. Tenant A: max 1000 req/min, 10 concurrent queries, 100GB data scanned/day.",
         "real_world": "AWS RDS: Per-instance IOPS limits. Heroku: Per-app dyno limits. Prevents noisy neighbor problems.",
         "zone_from": "Standard Application", "zone_to": "Critical",
         "stride_rule_applied": "Denial of Service: Flow from zone-3 (Query Service) to zone-7 (Data Warehouse) – any tenant can exhaust the shared critical resource",
         "owasp_categories": ["A04:2021 – Insecure Design", "A05:2021 – Security Misconfiguration"]},

        {"id": "T-204", "stride": "Information Disclosure", "component": "Data Lake → Data Warehouse",
         "threat": "Shared Secret Keys - all tenant data with same encryption key",
         "likelihood": "Medium", "impact": "Critical",
         "correct_mitigations": ["Per-tenant encryption keys (DEK per tenant)",
                                  "Separate backup files per tenant",
                                  "AWS KMS with tenant isolation",
                                  "Automatic key rotation"],
         "incorrect_mitigations": ["Single master key for all tenants", "Shared backups", "No key separation"],
         "explanation": "All tenants' data encrypted with same master key. If key leaked, ALL tenant data decryptable.",
         "compliance": "GDPR Article 32 (Security of processing), SOC 2 CC6.1",
         "points": 10,
         "why_this_risk": "Medium/critical - needs key compromise but exposes EVERYTHING.",
         "why_these_controls": "Each tenant has unique DEK. DEKs encrypted with tenant-specific KEK in AWS KMS.",
         "real_world": "GDPR requires data isolation. Multi-tenant SaaS with single key failed audit. Per-tenant keys now standard for enterprise SaaS.",
         "zone_from": "Critical", "zone_to": "Not in Control of System",
         "stride_rule_applied": "Information Disclosure: Critical zone (7) data store – a single compromised key exposes all tenants when keys are shared",
         "owasp_categories": ["A02:2021 – Cryptographic Failures"]},

        {"id": "T-205", "stride": "Tampering", "component": "API Gateway",
         "threat": "Insufficient Tenant Context Validation - accepting tenant_id from request",
         "likelihood": "High", "impact": "High",
         "correct_mitigations": ["Tenant-tagged logs with tenant_id in every log",
                                  "Isolation testing (automated tests with 2 tenants)",
                                  "Tenant context from JWT claims only",
                                  "Middleware enforcement"],
         "incorrect_mitigations": ["Trust request body tenant_id", "No isolation tests", "Optional tenant validation"],
         "explanation": "API accepts tenant_id from request body without validation. Attacker modifies POST body: {tenant_id: 'victim-tenant', data: {...}}",
         "compliance": "SOC 2 CC7.2 (System Monitoring)",
         "points": 10,
         "why_this_risk": "High/high - extremely common mistake. Direct data integrity and isolation issues.",
         "why_these_controls": "NEVER trust tenant_id from request body/query params. Extract from JWT claims only.",
         "real_world": "Isolation testing caught 40% of tenant isolation bugs in major SaaS platforms before production deployment.",
         "zone_from": "Not in Control of System", "zone_to": "Standard Application",
         "stride_rule_applied": "Tampering: Zone-0 tenant user sends POST request to zone-3 API Gateway – forged tenant_id in body tampers with tenant isolation boundary",
         "owasp_categories": ["A03:2021 – Injection", "A01:2021 – Broken Access Control"]}
    ],

    "4": [
        {"id": "T-301", "stride": "Tampering", "component": "Glucose Monitor → IoT Gateway",
         "threat": "Device Tampering - firmware modification or physical access",
         "likelihood": "Medium", "impact": "Critical",
         "correct_mitigations": ["Secure boot with signature verification",
                                  "Firmware signing with manufacturer key",
                                  "TPM (Trusted Platform Module)",
                                  "Physical tamper detection sensors"],
         "incorrect_mitigations": ["No firmware verification", "Unsigned firmware allowed", "No tamper seals"],
         "explanation": "Attacker gains physical access to glucose monitor. Reflashes firmware to report false readings.",
         "compliance": "FDA 21 CFR Part 11, IEC 62304 (medical device software)",
         "points": 10,
         "why_this_risk": "Medium/CRITICAL - needs physical access but LIFE-THREATENING. Patient could die from missed alerts.",
         "why_these_controls": "Secure boot verifies firmware signature before boot using hardware root of trust. Only signed firmware will execute.",
         "real_world": "Medtronic insulin pump recall: Unencrypted RF allowed unauthorized dosing. St. Jude pacemaker: Firmware could be modified remotely.",
         "zone_from": "Not in Control of System", "zone_to": "Minimal Trust",
         "stride_rule_applied": "Tampering: Physical device (zone 0 - patient home) to IoT Gateway (zone 1) – attacker with physical access tampers at the lowest trust boundary",
         "owasp_categories": ["A08:2021 – Software and Data Integrity Failures"]},

        {"id": "T-302", "stride": "Tampering", "component": "IoT Gateway → Device Data Svc",
         "threat": "Replay Attacks on Sensor Data - old readings replayed",
         "likelihood": "High", "impact": "Critical",
         "correct_mitigations": ["UTC timestamps on every message",
                                  "Nonce (number used once)",
                                  "Message freshness checks (reject >5min old)",
                                  "Sequence numbers (monotonic counter)"],
         "incorrect_mitigations": ["No timestamps", "Accept any message age", "No replay detection"],
         "explanation": "Attacker captures MQTT messages containing vital signs. Replays old 'normal' readings while patient's actual vitals are critical.",
         "compliance": "HIPAA 164.312(e)(2)(i), FDA Cybersecurity Guidance",
         "points": 10,
         "why_this_risk": "High/CRITICAL - easy to execute replay attack. Patient doesn't receive life-saving intervention. DEATH possible.",
         "why_these_controls": "Every sensor message includes UTC timestamp. Server rejects messages older than 5 minutes.",
         "real_world": "Medical device replay attacks demonstrated in research. ICS/SCADA systems compromised by replay.",
         "zone_from": "Minimal Trust", "zone_to": "Standard Application",
         "stride_rule_applied": "Tampering: IoT Gateway (zone 1) to Cloud Service (zone 3) – replayed messages tamper with the integrity of real-time patient data",
         "owasp_categories": ["A08:2021 – Software and Data Integrity Failures", "A02:2021 – Cryptographic Failures"]},

        {"id": "T-303", "stride": "Information Disclosure", "component": "Patient DB",
         "threat": "Unencrypted PHI/PII - database backups exposed",
         "likelihood": "Medium", "impact": "Critical",
         "correct_mitigations": ["AES-256 encryption at rest (HIPAA requirement)",
                                  "TLS 1.3 for all connections",
                                  "AWS KMS for key management",
                                  "Encrypted backups"],
         "incorrect_mitigations": ["No encryption", "Unencrypted backups", "Keys stored with data"],
         "explanation": "Database backups stored unencrypted in S3. Misconfiguration makes bucket public.",
         "compliance": "HIPAA 164.312(a)(2)(iv), HITECH Act",
         "points": 10,
         "why_this_risk": "Medium/critical - HIPAA breach notification required. Massive fines ($3M+ average). Patient privacy violated.",
         "why_these_controls": "AES-256 encryption for RDS, S3, EBS. HIPAA requirement - not optional.",
         "real_world": "Healthcare breaches: Anthem (78M records), Premera (11M records) - both unencrypted data. Average HIPAA breach fine: $3M+.",
         "zone_from": "Critical", "zone_to": "Not in Control of System",
         "stride_rule_applied": "Information Disclosure: Patient DB (zone 9 - Maximum Security) – PHI flows outward if backup misconfiguration collapses the zone boundary",
         "owasp_categories": ["A02:2021 – Cryptographic Failures", "A05:2021 – Security Misconfiguration"]},

        {"id": "T-304", "stride": "Denial of Service", "component": "Alert Service → Web Portal",
         "threat": "Alert Suppression - critical alerts not delivered",
         "likelihood": "Medium", "impact": "Critical",
         "correct_mitigations": ["Redundant alert channels (WebSocket + SMS + Phone)",
                                  "Priority queues (P0 critical, P1 urgent, P2 warning)",
                                  "Watchdog timers (2-minute timeout)",
                                  "Alert rate limiting (except P0)"],
         "incorrect_mitigations": ["Single channel only", "No prioritization", "No watchdog timers"],
         "explanation": "Attacker floods alert system with fake low-priority alerts. Queue fills up. Critical patient alert stuck in queue.",
         "compliance": "FDA 510(k) safety requirements, IEC 60601-1-8 (medical alarms)",
         "points": 10,
         "why_this_risk": "Medium/CRITICAL - needs system access but PATIENT SUFFERS PREVENTABLE HARM.",
         "why_these_controls": "Critical alerts sent via: 1) WebSocket to portal, 2) SMS to on-call, 3) Phone call (after 2 min), 4) Email. P0 alerts bypass rate limiting.",
         "real_world": "Alert fatigue causes 50-90% of alerts ignored. Proper prioritization saves lives.",
         "zone_from": "Standard Application", "zone_to": "Not in Control of System",
         "stride_rule_applied": "Denial of Service: Alert Service (zone 3) to Web Portal/Clinician (zone 0) – flooding the queue is a DoS on the safety-critical alert path",
         "owasp_categories": ["A04:2021 – Insecure Design", "A05:2021 – Security Misconfiguration"]},

        {"id": "T-305", "stride": "Tampering", "component": "HL7 Interface → Legacy EHR",
         "threat": "Legacy System Injection - HL7 v2 message manipulation",
         "likelihood": "High", "impact": "High",
         "correct_mitigations": ["HL7 message validation against specification",
                                  "Network isolation (separate VLAN)",
                                  "Site-to-site VPN for encryption",
                                  "Custom HMAC signatures in ZPD segment"],
         "incorrect_mitigations": ["No HL7 validation", "Open network access", "No encryption"],
         "explanation": "Legacy EHR uses HL7 v2 over MLLP (no encryption, no authentication). Attacker on hospital network injects malicious HL7 messages.",
         "compliance": "HIPAA, HL7 v2.x specification",
         "points": 10,
         "why_this_risk": "High/high - legacy systems often unpatched. Direct patient harm from prescription modification.",
         "why_these_controls": "Validate every HL7 segment against specification. VPN encrypts all traffic. Message signing provides integrity.",
         "real_world": "Hospital ransomware often exploits legacy systems. HL7 interfaces frequently lack authentication.",
         "zone_from": "Standard Application", "zone_to": "Not in Control of System",
         "stride_rule_applied": "Tampering: HL7 Interface (zone 3) injects malicious messages INTO Legacy EHR (zone 0 - uncontrolled, no auth). Although data flows zone 3 → zone 0 (normally Info Disclosure direction), this threat is Tampering because the ATTACKER is modifying the HL7 message contents en-route (network interception). The attacker sits between zones on the hospital network, making this a data-in-transit tampering attack.",
         "owasp_categories": ["A03:2021 – Injection", "A08:2021 – Software and Data Integrity Failures"]}
    ]
}


# ─────────────────────────────────────────────────────────────────────────────
# WORKSHOPS CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
WORKSHOPS = {
    "1": {
        "name": "Workshop 1: Web Application (2-Tier)",
        "architecture_type": "2-Tier Web Application",
        "level": "Foundation",
        "duration": "2 hours",
        "target_threats": 5,
        "unlock_requirement": None,
        "learning_objectives": [
            "Apply the 4-step Infosec threat modeling methodology end-to-end",
            "Label system components with Criticality Zones (0–9 scale)",
            "Apply STRIDE rules based on zone relationships and element types",
            "Map identified threats to OWASP Top 10 controls",
            "Understand why each STRIDE category applies to specific DFD elements"
        ],
        "scenario": {
            "title": "TechMart E-Commerce Store",
            "description": "React frontend + Node.js API + PostgreSQL database",
            "business_context": "Series A startup, 50K monthly users, $2M revenue",
            "assets": ["Customer PII", "Payment data", "User credentials", "Order history"],
            "objectives": ["Confidentiality: Protect customer PII",
                           "Integrity: Order accuracy",
                           "Availability: 99.5% uptime"],
            "compliance": ["PCI-DSS Level 4", "GDPR", "CCPA"],
            "components": [
                {"name": "Customer", "type": "external_entity",
                 "description": "End users (untrusted)", "zone": "Not in Control of System", "zone_score": 0},
                {"name": "Web Frontend", "type": "process",
                 "description": "React SPA in browser", "zone": "Minimal Trust", "zone_score": 1},
                {"name": "API Backend", "type": "process",
                 "description": "Node.js/Express", "zone": "Standard Application", "zone_score": 3},
                {"name": "Database", "type": "datastore",
                 "description": "PostgreSQL – stores PII & orders", "zone": "Critical", "zone_score": 7},
                {"name": "Stripe", "type": "external_entity",
                 "description": "3rd-party payment processor", "zone": "Not in Control of System", "zone_score": 0},
                {"name": "SendGrid", "type": "external_entity",
                 "description": "3rd-party email service", "zone": "Not in Control of System", "zone_score": 0}
            ],
            "data_flows": [
                {"source": "Customer", "destination": "Web Frontend",
                 "data": "Requests/input", "protocol": "HTTPS"},
                {"source": "Web Frontend", "destination": "API Backend",
                 "data": "API calls", "protocol": "HTTPS"},
                {"source": "API Backend", "destination": "Database",
                 "data": "SQL queries", "protocol": "PostgreSQL"},
                {"source": "API Backend", "destination": "Stripe",
                 "data": "Payment data", "protocol": "HTTPS"},
                {"source": "API Backend", "destination": "SendGrid",
                 "data": "Email content", "protocol": "HTTPS"},
                {"source": "Database", "destination": "API Backend",
                 "data": "Query results", "protocol": "PostgreSQL"}
            ],
            "trust_boundaries": [
                {"name": "Internet Boundary",
                 "description": "Zone 0 (Untrusted Internet) → Zone 1 (Frontend)",
                 "components": ["Customer", "Web Frontend"]},
                {"name": "Application Boundary",
                 "description": "Zone 1 (Frontend) → Zone 3 (API Backend)",
                 "components": ["Web Frontend", "API Backend"]},
                {"name": "Data Boundary",
                 "description": "Zone 3 (Application) → Zone 7 (Database)",
                 "components": ["API Backend", "Database"]}
            ]
        }
    },
    "2": {
        "name": "Workshop 2: Microservices / API-Based",
        "architecture_type": "Microservices Architecture",
        "level": "Intermediate",
        "duration": "2 hours",
        "target_threats": 5,
        "unlock_requirement": "1",
        "learning_objectives": [
            "Apply zone-based STRIDE rules to service mesh architectures",
            "Identify BOLA and service impersonation threats using zone analysis",
            "Understand how mTLS enforces zone trust boundaries in microservices",
            "Map distributed tracing requirements to Repudiation prevention",
            "Apply OWASP API Security Top 10 alongside OWASP Top 10"
        ],
        "scenario": {
            "title": "CloudBank Mobile Banking",
            "description": "API Gateway + Multiple Services + Message Queues",
            "business_context": "Regional bank, 500K customers",
            "assets": ["Financial data", "Transactions", "PII", "OAuth tokens"],
            "objectives": ["Confidentiality", "Integrity", "Availability: 99.95%"],
            "compliance": ["PCI-DSS", "SOC 2", "GLBA"],
            "components": [
                {"name": "Mobile App", "type": "external_entity",
                 "description": "iOS/Android client", "zone": "Not in Control of System", "zone_score": 0},
                {"name": "API Gateway", "type": "process",
                 "description": "AWS API Gateway – entry point", "zone": "Minimal Trust", "zone_score": 1},
                {"name": "User Service", "type": "process",
                 "description": "Auth & identity (ECS)", "zone": "Elevated Trust", "zone_score": 5},
                {"name": "Payment Service", "type": "process",
                 "description": "Financial transfers (ECS)", "zone": "Elevated Trust", "zone_score": 5},
                {"name": "User DB", "type": "datastore",
                 "description": "DynamoDB – user profiles", "zone": "Critical", "zone_score": 7},
                {"name": "Transaction DB", "type": "datastore",
                 "description": "Aurora – financial records", "zone": "Critical", "zone_score": 8}
            ],
            "data_flows": [
                {"source": "Mobile App", "destination": "API Gateway",
                 "data": "HTTPS requests", "protocol": "HTTPS"},
                {"source": "API Gateway", "destination": "User Service",
                 "data": "Auth requests", "protocol": "HTTP/2 + mTLS"},
                {"source": "API Gateway", "destination": "Payment Service",
                 "data": "Payment requests", "protocol": "HTTP/2 + mTLS"},
                {"source": "User Service", "destination": "User DB",
                 "data": "User data", "protocol": "DynamoDB SDK"},
                {"source": "Payment Service", "destination": "Transaction DB",
                 "data": "Transactions", "protocol": "PostgreSQL"},
                {"source": "User Service", "destination": "Payment Service",
                 "data": "Auth tokens", "protocol": "HTTP/2"}
            ],
            "trust_boundaries": [
                {"name": "Client Boundary",
                 "description": "Zone 0 (Mobile App) → Zone 1 (API Gateway)",
                 "components": ["Mobile App", "API Gateway"]},
                {"name": "Service Mesh Boundary",
                 "description": "Zone 1 → Zone 5 (Microservices)",
                 "components": ["API Gateway", "User Service", "Payment Service"]},
                {"name": "Data Boundary",
                 "description": "Zone 5 (Services) → Zone 7–8 (Databases)",
                 "components": ["User DB", "Transaction DB"]}
            ]
        }
    },
    "3": {
        "name": "Workshop 3: Multi-Tenant SaaS",
        "architecture_type": "Multi-Tenant SaaS",
        "level": "Advanced",
        "duration": "2 hours",
        "target_threats": 5,
        "unlock_requirement": "2",
        "learning_objectives": [
            "Identify unique threats when multiple tenants share infrastructure",
            "Apply zone rules to detect cross-tenant data leakage paths",
            "Design tenant isolation using database-level Row-Level Security",
            "Understand how STRIDE Elevation of Privilege maps to tenant context bypass",
            "Master the SOC 2 and ISO 27001 compliance implications of multi-tenancy"
        ],
        "scenario": {
            "title": "DataInsight Analytics Platform",
            "description": "Shared infrastructure with logical tenant isolation",
            "business_context": "B2B SaaS, 500 enterprise customers",
            "assets": ["Business intelligence data", "Tenant metadata", "API keys", "Proprietary analytics"],
            "objectives": ["Tenant isolation", "Data integrity", "99.99% SLA"],
            "compliance": ["SOC 2 Type II", "ISO 27001", "GDPR"],
            "components": [
                {"name": "Web Dashboard", "type": "external_entity",
                 "description": "React SPA (tenant user)", "zone": "Not in Control of System", "zone_score": 0},
                {"name": "API Gateway", "type": "process",
                 "description": "Kong – tenant routing", "zone": "Minimal Trust", "zone_score": 2},
                {"name": "Ingestion Service", "type": "process",
                 "description": "Data ingestion (shared)", "zone": "Standard Application", "zone_score": 3},
                {"name": "Query Service", "type": "process",
                 "description": "Analytics query engine", "zone": "Standard Application", "zone_score": 3},
                {"name": "Kafka", "type": "datastore",
                 "description": "MSK streaming – shared topics", "zone": "Elevated Trust", "zone_score": 5},
                {"name": "Data Warehouse", "type": "datastore",
                 "description": "Redshift – ALL tenant data", "zone": "Critical", "zone_score": 8}
            ],
            "data_flows": [
                {"source": "Web Dashboard", "destination": "API Gateway",
                 "data": "Tenant requests", "protocol": "HTTPS"},
                {"source": "API Gateway", "destination": "Ingestion Service",
                 "data": "Data upload", "protocol": "HTTPS"},
                {"source": "Ingestion Service", "destination": "Kafka",
                 "data": "Events", "protocol": "Kafka protocol"},
                {"source": "Kafka", "destination": "Query Service",
                 "data": "Streaming data", "protocol": "Kafka Consumer"},
                {"source": "Query Service", "destination": "Data Warehouse",
                 "data": "SQL queries", "protocol": "Redshift JDBC"},
                {"source": "Data Warehouse", "destination": "Query Service",
                 "data": "Query results", "protocol": "Redshift JDBC"}
            ],
            "trust_boundaries": [
                {"name": "Tenant Boundary",
                 "description": "Zone 0 (Tenant User) → Zone 2 (API Gateway)",
                 "components": ["Web Dashboard", "API Gateway"]},
                {"name": "Isolation Boundary",
                 "description": "Zone 2-3 (Services) ← MUST enforce tenant_id →",
                 "components": ["Ingestion Service", "Query Service", "Kafka"]},
                {"name": "Shared Data Boundary",
                 "description": "Zone 3-5 → Zone 8 (Data Warehouse – ALL tenant data)",
                 "components": ["Kafka", "Data Warehouse"]}
            ]
        }
    },
    "4": {
        "name": "Workshop 4: IoT / Healthcare Systems",
        "architecture_type": "IoT / Healthcare",
        "level": "Expert",
        "duration": "2 hours",
        "target_threats": 5,
        "unlock_requirement": "3",
        "learning_objectives": [
            "Apply Maximum Security (zone 9) designations to life-critical components",
            "Understand physical trust boundaries in IoT device environments",
            "Map STRIDE threats to FDA medical device cybersecurity requirements",
            "Identify how replay attacks bypass zone boundaries in safety-critical systems",
            "Design redundant safety-critical alert delivery against DoS threats"
        ],
        "scenario": {
            "title": "HealthMonitor Connected Care",
            "description": "IoT Devices + Edge Gateway + Cloud + Legacy Integration",
            "business_context": "FDA-registered device, 10K patients",
            "assets": ["PHI (HIPAA-regulated)", "Vital signs (safety-critical)",
                       "Device calibration data", "Clinical alert state"],
            "objectives": ["Safety: Data integrity (HIGHEST PRIORITY)",
                           "Privacy: PHI protection",
                           "Availability: 99.99% (life-critical)"],
            "compliance": ["HIPAA", "FDA 21 CFR Part 11", "HITECH", "IEC 62304"],
            "components": [
                {"name": "Glucose Monitor", "type": "external_entity",
                 "description": "CGM device (patient home – physical access)", "zone": "Not in Control of System", "zone_score": 0},
                {"name": "IoT Gateway", "type": "process",
                 "description": "Edge device (patient home)", "zone": "Minimal Trust", "zone_score": 1},
                {"name": "Device Data Svc", "type": "process",
                 "description": "Cloud telemetry processor", "zone": "Standard Application", "zone_score": 4},
                {"name": "Alert Service", "type": "process",
                 "description": "SAFETY-CRITICAL alert dispatch", "zone": "Maximum Security", "zone_score": 9},
                {"name": "Patient DB", "type": "datastore",
                 "description": "Aurora – PHI (HIPAA)", "zone": "Maximum Security", "zone_score": 9},
                {"name": "Web Portal", "type": "external_entity",
                 "description": "Clinician portal", "zone": "Not in Control of System", "zone_score": 0},
                {"name": "Legacy EHR", "type": "external_entity",
                 "description": "Hospital EHR via HL7 v2", "zone": "Not in Control of System", "zone_score": 0}
            ],
            "data_flows": [
                {"source": "Glucose Monitor", "destination": "IoT Gateway",
                 "data": "Glucose readings", "protocol": "BLE"},
                {"source": "IoT Gateway", "destination": "Device Data Svc",
                 "data": "Vital signs telemetry", "protocol": "MQTT/TLS"},
                {"source": "Device Data Svc", "destination": "Alert Service",
                 "data": "Alert events", "protocol": "HTTP/2"},
                {"source": "Alert Service", "destination": "Web Portal",
                 "data": "Clinical alerts", "protocol": "WebSocket"},
                {"source": "Device Data Svc", "destination": "Patient DB",
                 "data": "PHI records", "protocol": "PostgreSQL"},
                {"source": "Device Data Svc", "destination": "Legacy EHR",
                 "data": "HL7 messages", "protocol": "MLLP/HL7v2"}
            ],
            "trust_boundaries": [
                {"name": "Physical Device Boundary",
                 "description": "Zone 0 (Physical device at patient home) → Zone 1 (IoT Gateway)",
                 "components": ["Glucose Monitor", "IoT Gateway"]},
                {"name": "Edge-to-Cloud Boundary",
                 "description": "Zone 1 (Edge) → Zone 4 (Cloud processing)",
                 "components": ["IoT Gateway", "Device Data Svc"]},
                {"name": "Safety-Critical Boundary",
                 "description": "Zone 4 → Zone 9 (Life-critical systems – Maximum Security)",
                 "components": ["Alert Service", "Patient DB"]}
            ]
        }
    }
}


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK TREES
# ─────────────────────────────────────────────────────────────────────────────
ATTACK_TREES = {
    "1": {
        "title": "Attack Tree: Compromise E-Commerce Platform",
        "description": "Complete attack tree showing multiple paths to steal customer payment data from TechMart",
        "tree": {
            "type": "goal", "label": "GOAL: Steal Customer\nPayment Data",
            "children": [
                {"type": "or", "label": "Compromise Database",
                 "children": [
                     {"type": "and", "label": "SQL Injection Attack",
                      "children": [
                          {"type": "leaf", "label": "Find injectable\nparameter", "difficulty": "Easy"},
                          {"type": "leaf", "label": "Bypass input\nvalidation", "difficulty": "Medium"},
                          {"type": "leaf", "label": "Extract data via\nUNION query", "difficulty": "Easy"}
                      ]},
                     {"type": "and", "label": "Steal Database Backup",
                      "children": [
                          {"type": "leaf", "label": "Find misconfigured\nS3 bucket", "difficulty": "Medium"},
                          {"type": "leaf", "label": "Download backup\nfile", "difficulty": "Easy"},
                          {"type": "leaf", "label": "Decrypt if\nencrypted", "difficulty": "Hard"}
                      ]}
                 ]},
                {"type": "or", "label": "Intercept Data in Transit",
                 "children": [
                     {"type": "and", "label": "Man-in-the-Middle",
                      "children": [
                          {"type": "leaf", "label": "Position on\nnetwork path", "difficulty": "Hard"},
                          {"type": "leaf", "label": "Downgrade to HTTP\nor weak TLS", "difficulty": "Medium"},
                          {"type": "leaf", "label": "Capture payment\ndata", "difficulty": "Easy"}
                      ]},
                     {"type": "and", "label": "XSS + Session Hijacking",
                      "children": [
                          {"type": "leaf", "label": "Inject XSS payload\nin search/comments", "difficulty": "Medium"},
                          {"type": "leaf", "label": "Steal session\ncookie", "difficulty": "Easy"},
                          {"type": "leaf", "label": "Access user account\n& payment methods", "difficulty": "Easy"}
                      ]}
                 ]},
                {"type": "or", "label": "Compromise API Backend",
                 "children": [
                     {"type": "and", "label": "Exploit Admin Panel",
                      "children": [
                          {"type": "leaf", "label": "Find admin\nendpoint", "difficulty": "Easy"},
                          {"type": "leaf", "label": "Bypass authorization\ncheck", "difficulty": "Medium"},
                          {"type": "leaf", "label": "Export customer\ndata", "difficulty": "Easy"}
                      ]},
                     {"type": "and", "label": "API Key Exposure",
                      "children": [
                          {"type": "leaf", "label": "Find hardcoded keys\nin frontend code", "difficulty": "Easy"},
                          {"type": "leaf", "label": "Use Stripe secret\nkey", "difficulty": "Easy"},
                          {"type": "leaf", "label": "Create fraudulent\ncharges", "difficulty": "Easy"}
                      ]}
                 ]}
            ]
        }
    },
    "2": {
        "title": "Attack Tree: Unauthorized Fund Transfer",
        "description": "Attack tree for stealing money from mobile banking application",
        "tree": {
            "type": "goal", "label": "GOAL: Unauthorized\nFund Transfer",
            "children": [
                {"type": "or", "label": "Exploit API Authorization",
                 "children": [
                     {"type": "and", "label": "BOLA Attack",
                      "children": [
                          {"type": "leaf", "label": "Enumerate account\nIDs", "difficulty": "Easy"},
                          {"type": "leaf", "label": "Access other user's\ntransaction API", "difficulty": "Easy"},
                          {"type": "leaf", "label": "Initiate transfer from\nvictim account", "difficulty": "Medium"}
                      ]},
                     {"type": "and", "label": "Token Theft from Mobile",
                      "children": [
                          {"type": "leaf", "label": "Install malware on\nuser device", "difficulty": "Hard"},
                          {"type": "leaf", "label": "Extract JWT from\napp storage", "difficulty": "Medium"},
                          {"type": "leaf", "label": "Replay token to\nAPI Gateway", "difficulty": "Easy"}
                      ]}
                 ]},
                {"type": "or", "label": "Exploit Service Mesh",
                 "children": [
                     {"type": "and", "label": "Service Impersonation",
                      "children": [
                          {"type": "leaf", "label": "Gain access to\nKubernetes cluster", "difficulty": "Hard"},
                          {"type": "leaf", "label": "Deploy rogue\nPayment Service", "difficulty": "Medium"},
                          {"type": "leaf", "label": "Intercept transfer\nrequests", "difficulty": "Easy"}
                      ]},
                     {"type": "and", "label": "Replay Transaction",
                      "children": [
                          {"type": "leaf", "label": "Capture valid\ntransaction token", "difficulty": "Medium"},
                          {"type": "leaf", "label": "Replay to Payment\nService", "difficulty": "Easy"},
                          {"type": "leaf", "label": "Double-process\ntransfer", "difficulty": "Easy"}
                      ]}
                 ]},
                {"type": "or", "label": "Bypass Rate Limiting",
                 "children": [
                     {"type": "and", "label": "Distributed Attack",
                      "children": [
                          {"type": "leaf", "label": "Rent botnet with\n10K+ IPs", "difficulty": "Medium"},
                          {"type": "leaf", "label": "Bypass per-IP\nrate limits", "difficulty": "Easy"},
                          {"type": "leaf", "label": "Brute force account\ncredentials", "difficulty": "Medium"}
                      ]}
                 ]}
            ]
        }
    },
    "3": {
        "title": "Attack Tree: Cross-Tenant Data Breach",
        "description": "Attack tree for accessing competitor's business intelligence data in SaaS platform",
        "tree": {
            "type": "goal", "label": "GOAL: Access Competitor's\nBusiness Data",
            "children": [
                {"type": "or", "label": "SQL Injection Bypass",
                 "children": [
                     {"type": "and", "label": "Remove Tenant Filter",
                      "children": [
                          {"type": "leaf", "label": "Find custom SQL\nquery endpoint", "difficulty": "Easy"},
                          {"type": "leaf", "label": "Inject SQL to remove\ntenant_id filter", "difficulty": "Medium"},
                          {"type": "leaf", "label": "Extract all tenants'\ndata", "difficulty": "Easy"}
                      ]},
                     {"type": "and", "label": "Bypass RLS Policy",
                      "children": [
                          {"type": "leaf", "label": "Find DB without\nRLS configured", "difficulty": "Medium"},
                          {"type": "leaf", "label": "Direct query without\ntenant context", "difficulty": "Medium"},
                          {"type": "leaf", "label": "Access Redshift\nwithout filters", "difficulty": "Easy"}
                      ]}
                 ]},
                {"type": "or", "label": "Tenant Context Manipulation",
                 "children": [
                     {"type": "and", "label": "JWT Token Tampering",
                      "children": [
                          {"type": "leaf", "label": "Capture own JWT\ntoken", "difficulty": "Easy"},
                          {"type": "leaf", "label": "Modify tenant_id\nclaim", "difficulty": "Hard"},
                          {"type": "leaf", "label": "Re-sign with weak\nkey", "difficulty": "Hard"}
                      ]},
                     {"type": "and", "label": "Request Body Injection",
                      "children": [
                          {"type": "leaf", "label": "Find API accepting\ntenant_id in body", "difficulty": "Medium"},
                          {"type": "leaf", "label": "Change tenant_id to\ntarget tenant", "difficulty": "Easy"},
                          {"type": "leaf", "label": "Write/read data in\nvictim tenant", "difficulty": "Easy"}
                      ]}
                 ]},
                {"type": "or", "label": "Shared Resource Access",
                 "children": [
                     {"type": "and", "label": "Kafka Topic Cross-Read",
                      "children": [
                          {"type": "leaf", "label": "Access shared Kafka\ncluster", "difficulty": "Medium"},
                          {"type": "leaf", "label": "Subscribe to all\ntopics (no ACL)", "difficulty": "Easy"},
                          {"type": "leaf", "label": "Read cross-tenant\nmessages", "difficulty": "Easy"}
                      ]},
                     {"type": "and", "label": "Shared Encryption Key",
                      "children": [
                          {"type": "leaf", "label": "Compromise own\ntenant DEK", "difficulty": "Hard"},
                          {"type": "leaf", "label": "Discover same key\nused for all", "difficulty": "Easy"},
                          {"type": "leaf", "label": "Decrypt competitor\nbackups", "difficulty": "Easy"}
                      ]}
                 ]}
            ]
        }
    },
    "4": {
        "title": "Attack Tree: Patient Harm via Medical Device",
        "description": "Attack tree showing paths to cause patient harm through device compromise",
        "tree": {
            "type": "goal", "label": "GOAL: Cause Patient Harm\nvia Device Compromise",
            "children": [
                {"type": "or", "label": "Suppress Critical Alerts",
                 "children": [
                     {"type": "and", "label": "Alert Flooding DoS",
                      "children": [
                          {"type": "leaf", "label": "Gain network access\nto alert system", "difficulty": "Hard"},
                          {"type": "leaf", "label": "Flood queue with\nfake P2 alerts", "difficulty": "Easy"},
                          {"type": "leaf", "label": "P0 cardiac arrest\nalert delayed", "difficulty": "Easy"}
                      ]},
                     {"type": "and", "label": "Replay Normal Readings",
                      "children": [
                          {"type": "leaf", "label": "Capture MQTT vitals\nmessages", "difficulty": "Medium"},
                          {"type": "leaf", "label": "Replay old 'normal'\nreadings", "difficulty": "Easy"},
                          {"type": "leaf", "label": "Critical vitals\nnot reported", "difficulty": "Easy"}
                      ]}
                 ]},
                {"type": "or", "label": "Tamper with Device",
                 "children": [
                     {"type": "and", "label": "Physical Firmware Mod",
                      "children": [
                          {"type": "leaf", "label": "Physical access to\nglucose monitor", "difficulty": "Medium"},
                          {"type": "leaf", "label": "Bypass secure boot\nor remove TPM", "difficulty": "Hard"},
                          {"type": "leaf", "label": "Flash malicious\nfirmware", "difficulty": "Medium"},
                          {"type": "leaf", "label": "Device reports false\n'normal' readings", "difficulty": "Easy"}
                      ]},
                     {"type": "and", "label": "BLE MITM Attack",
                      "children": [
                          {"type": "leaf", "label": "Position within BLE\nrange (~10m)", "difficulty": "Easy"},
                          {"type": "leaf", "label": "Exploit unencrypted\nBLE pairing", "difficulty": "Medium"},
                          {"type": "leaf", "label": "Inject false glucose\nreadings", "difficulty": "Medium"}
                      ]}
                 ]},
                {"type": "or", "label": "Inject HL7 Messages",
                 "children": [
                     {"type": "and", "label": "Hospital Network Attack",
                      "children": [
                          {"type": "leaf", "label": "Access hospital\nnetwork (phishing)", "difficulty": "Medium"},
                          {"type": "leaf", "label": "Locate HL7 interface\non VLAN", "difficulty": "Medium"},
                          {"type": "leaf", "label": "Inject malicious HL7\nmessage", "difficulty": "Easy"},
                          {"type": "leaf", "label": "Modify prescription\nto lethal dose", "difficulty": "Easy"}
                      ]}
                 ]}
            ]
        }
    }
}


# ─────────────────────────────────────────────────────────────────────────────
# DIAGRAM GENERATORS
# ─────────────────────────────────────────────────────────────────────────────
ZONE_COLORS = {
    "Not in Control of System": "#F6F5F4",
    "Minimal Trust": "#CAE4CB",
    "Standard Application": "#FBF5C8",
    "Elevated Trust": "#F9DFB8",
    "Critical": "#FBD1D5",
    "Maximum Security": "#C73B3B"
}

ZONE_FONT_COLORS = {
    "Not in Control of System": "black",
    "Minimal Trust": "black",
    "Standard Application": "black",
    "Elevated Trust": "black",
    "Critical": "black",
    "Maximum Security": "white"
}




# ─────────────────────────────────────────────────────────────────────────────
# DRAW.IO-STYLE ARCHITECTURE DIAGRAM (SVG, fully dynamic from workshop config)
# ─────────────────────────────────────────────────────────────────────────────

def get_component_icon(comp_type):
    """Return SVG path / shape info based on component type."""
    return {
        "external_entity": "ellipse",
        "process":         "rect",
        "datastore":       "cylinder",
    }.get(comp_type, "rect")


def _zone_hex(zone_name):
    return {
        "Not in Control of System": "#EFEEED",
        "Minimal Trust":            "#CAE4CB",
        "Standard Application":     "#FBF5C8",
        "Elevated Trust":           "#F9DFB8",
        "Critical":                 "#FBD1D5",
        "Maximum Security":         "#F7AF99",
    }.get(zone_name, "#F1F0EF")


def _zone_stroke(zone_name):
    return {
        "Not in Control of System": "#A6A196",
        "Minimal Trust":            "#3E8842",
        "Standard Application":     "#E9A435",
        "Elevated Trust":           "#D55611",
        "Critical":                 "#BA3434",
        "Maximum Security":         "#B23D19",
    }.get(zone_name, "#35A091")


def _xml(s):
    """Escape string for SVG text content."""
    return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")

# ── Zone visual config ─────────────────────────────────────────────────────
_ZONE_STYLE = {
    "Not in Control of System": {"fill":"#EFEFEE","stroke":"#948D80","dark":"#48453E","band":"#D8D6D3"},
    "Minimal Trust":            {"fill":"#EFEFEE","stroke":"#418544","dark":"#225726","band":"#CBE3CC"},
    "Standard Application":     {"fill":"#FDFBE9","stroke":"#E4A33A","dark":"#CF5817","band":"#F9F4CA"},
    "Elevated Trust":           {"fill":"#FCF2E3","stroke":"#D2552E","dark":"#AD401E","band":"#F8D0C3"},
    "Critical":                 {"fill":"#FDEDEF","stroke":"#B63838","dark":"#A82B2B","band":"#FAD2D6"},
    "Maximum Security":         {"fill":"#F7EAEB","stroke":"#7C1A4E","dark":"#44142A","band":"#F2C1D9"},
}
_ZONE_ORDER = [
    "Not in Control of System",
    "Minimal Trust",
    "Standard Application",
    "Elevated Trust",
    "Critical",
    "Maximum Security",
]
STRIDE_LETTERS = ["S", "T", "R", "I", "D", "E"]
STRIDE_NAMES = {"S": "Spoofing", "T": "Tampering", "R": "Repudiation", "I": "Information Disclosure",
                "D": "Denial of Service", "E": "Elevation of Privilege"}
STRIDE_LETTER_OF = {v: k for k, v in STRIDE_NAMES.items()}
_STRIDE_TAG_COLOR = {"S": "#762C95", "T": "#CF5817", "R": "#0C6D62", "I": "#2666AF", "D": "#B1295F", "E": "#5B574E"}
_STRIDE_TAG_TIP = STRIDE_NAMES
# STRIDE-per-element: which categories can apply to which kind of DFD element
STRIDE_PER_ELEMENT = {"external_entity": "SR", "process": "STRIDE", "datastore": "TRID", "flow": "TID"}
STRIDE_ELEMENT_NOTE = {
    "external_entity": "External entities can be spoofed (S) and can deny their actions (R); you do not control their internals.",
    "process": "Processes are exposed to all six categories.",
    "datastore": "Data stores: tampering (T), information disclosure (I) and DoS (D); repudiation (R) only when the store holds logs/audit data.",
    "flow": "Data flows: tampering (T), information disclosure (I) and DoS (D). Spoofing and EoP belong to the endpoints, not the line.",
}

# ── Nested trust-boundary trees (one per lab). Strings are component names. ─────────────────
BOUNDARY_TREES = {
    "1": {"children": [
        {"name": "Internet", "trust": "untrusted", "kind": "internet", "children": ["Customer"]},
        {"name": "User's Browser", "trust": "minimal trust", "children": ["Web Frontend"]},
        {"name": "TechMart Cloud (AWS)", "trust": "our infrastructure", "kind": "cloud", "dir": "col", "children": [
            {"name": "Application Tier", "children": ["API Backend"]},
            {"name": "Data Tier", "children": ["Database"]}]},
        {"name": "Third-Party Services", "trust": "vendor-controlled", "kind": "third_party", "dir": "col",
         "children": ["Stripe", "SendGrid"]}]},
    "2": {"children": [
        {"name": "Mobile Device", "trust": "untrusted device", "kind": "internet", "children": [
            {"name": "App Sandbox", "children": ["Mobile App"]}]},
        {"name": "CloudBank Cloud (AWS)", "trust": "our infrastructure", "kind": "cloud", "dir": "row", "children": [
            {"name": "Edge", "children": ["API Gateway"]},
            {"name": "Service Mesh (ECS)", "dir": "col", "children": ["User Service", "Payment Service"]},
            {"name": "Data Layer", "dir": "col", "children": ["User DB", "Transaction DB"]}]}]},
    "3": {"children": [
        {"name": "Tenant Users (Internet)", "trust": "untrusted", "kind": "internet", "children": ["Web Dashboard"]},
        {"name": "SaaS Platform (AWS)", "trust": "shared infrastructure", "kind": "cloud", "dir": "row", "children": [
            {"name": "Edge", "children": ["API Gateway"]},
            {"name": "Tenant-Aware Services", "dir": "col", "children": ["Ingestion Service", "Query Service"]},
            {"name": "Shared Data Plane", "dir": "col", "children": ["Kafka", "Data Warehouse"]}]}]},
    "4": {"children": [
        {"name": "Patient Home", "trust": "physical access", "kind": "internet", "dir": "col",
         "children": ["Glucose Monitor", "IoT Gateway"]},
        {"name": "HealthMonitor Cloud", "trust": "our infrastructure", "kind": "cloud", "dir": "row", "children": [
            {"name": "Cloud Processing", "children": ["Device Data Svc"]},
            {"name": "Safety-Critical Zone", "trust": "life-critical", "dir": "col", "children": ["Alert Service", "Patient DB"]}]},
        {"name": "Hospital / Clinic", "trust": "partner network", "kind": "third_party", "dir": "col",
         "children": ["Web Portal", "Legacy EHR"]}]},
}

_FONT = "'Inter','Segoe UI',Helvetica,Arial,sans-serif"
_MONO = "'JetBrains Mono',Consolas,'Courier New',monospace"
LEAF_W, PADG, TITLE_H, PADB = 156, 16, 52, 34
GAP_ROW_IN, GAP_COL_IN, GAP_TOP, MARG_X = 84, 72, 112, 34
_TOP = 34

ANNOTATION_KINDS = {
    "actor":   {"prefix": "TA", "title": "Threat Actor",         "icon": "🎭", "fill": "#D34A47", "stroke": "#A82B2B", "text": "#121110"},
    "asset":   {"prefix": "A",  "title": "Asset",                "icon": "💎", "fill": "#6EB272", "stroke": "#367539", "text": "#121110"},
    "threat":  {"prefix": "TS", "title": "Threat Scenario",      "icon": "⚡", "fill": "#E4BB55", "stroke": "#A77F1C", "text": "#121110"},
    "control": {"prefix": "C",  "title": "Control / Mitigation", "icon": "🛡️", "fill": "#E0A138", "stroke": "#A06712", "text": "#121110"},
}
_KIND_ORDER = ["actor", "asset", "threat", "control"]


def _trunc(s, n):
    s = str(s or "")
    return s if len(s) <= n else s[: max(1, n - 1)] + "…"


def _flow_key(flow):
    return f"{flow['source']} → {flow['destination']}"


def _ann_sort(item):
    try:
        num = int(re.sub(r"\D", "", item["id"]) or 0)
    except ValueError:
        num = 0
    return (_KIND_ORDER.index(item["kind"]) if item["kind"] in _KIND_ORDER else 9, num)


def _ws_id_of(cfg):
    t = cfg["scenario"]["title"]
    return next((k for k, v in WORKSHOPS.items() if v["scenario"]["title"] == t), None)


def _tree_for(cfg):
    ws = _ws_id_of(cfg)
    if ws in BOUNDARY_TREES:
        return BOUNDARY_TREES[ws]
    zones = {}
    for c in cfg["scenario"]["components"]:
        zones.setdefault(c.get("zone", "Zone"), []).append(c["name"])
    return {"children": [{"name": z, "children": names} for z, names in zones.items()]}


def element_ids(scn):
    pre = {"external_entity": "E", "process": "P", "datastore": "D"}
    ctr, ids = {}, {}
    for c in scn["components"]:
        ctr[c["type"]] = ctr.get(c["type"], 0) + 1
        ids[c["name"]] = f"{pre.get(c['type'], 'X')}{ctr[c['type']]}"
    for i, f in enumerate(scn["data_flows"], 1):
        ids[_flow_key(f)] = f"F{i}"
    return ids


def element_kind(scn, key):
    if "→" in key:
        return "flow"
    return next((c["type"] for c in scn["components"] if c["name"] == key), "process")


def _leaf_h(ctype):
    return 66 if ctype == "datastore" else 58


def _measure(node, cmap):
    if isinstance(node, str):
        return {"leaf": True, "name": node, "w": LEAF_W, "h": _leaf_h(cmap[node]["type"])}
    kids = [_measure(k, cmap) for k in node["children"]]
    d = node.get("dir", "col")
    if d == "row":
        cw = sum(k["w"] for k in kids) + GAP_ROW_IN * (len(kids) - 1)
        ch = max(k["h"] for k in kids)
    else:
        cw = max(k["w"] for k in kids)
        ch = sum(k["h"] for k in kids) + GAP_COL_IN * (len(kids) - 1)
    title_w = len(node["name"]) * 6.9 + (len(node.get("trust", "")) * 5.6 + 26 if node.get("trust") else 0) + 2 * PADG
    cw = max(cw, title_w - 2 * PADG)
    return {"leaf": False, "node": node, "kids": kids, "dir": d, "cw": cw, "ch": ch, "w": cw + 2 * PADG, "h": ch + TITLE_H + PADB}


def _place(m, x, y, path, leaves, groups):
    if m["leaf"]:
        leaves[m["name"]] = {"x": x, "y": y, "w": m["w"], "h": m["h"], "cx": x + m["w"] / 2, "cy": y + m["h"] / 2, "path": list(path)}
        return
    nd = m["node"]
    groups.append({"name": nd["name"], "trust": nd.get("trust", ""), "kind": nd.get("kind", ""), "x": x, "y": y,
                   "w": m["w"], "h": m["h"], "depth": len(path), "path": list(path) + [nd["name"]]})
    inner_x, inner_y = x + PADG, y + TITLE_H
    sub = list(path) + [nd["name"]]
    if m["dir"] == "row":
        total = sum(k["w"] for k in m["kids"]) + GAP_ROW_IN * (len(m["kids"]) - 1)
        cx_ = inner_x + (m["cw"] - total) / 2
        for k in m["kids"]:
            _place(k, cx_, inner_y + (m["ch"] - k["h"]) / 2, sub, leaves, groups)
            cx_ += k["w"] + GAP_ROW_IN
    else:
        cy_ = inner_y
        for k in m["kids"]:
            _place(k, inner_x + (m["cw"] - k["w"]) / 2, cy_, sub, leaves, groups)
            cy_ += k["h"] + GAP_COL_IN


def layout_tree(cfg):
    """Return {'leaves': {name: rect}, 'groups': [rect...], 'W', 'H'} with y starting at 0."""
    cmap = {c["name"]: c for c in cfg["scenario"]["components"]}
    tree = _tree_for(cfg)
    kids = [_measure(k, cmap) for k in tree["children"]]
    total = sum(k["w"] for k in kids) + GAP_TOP * (len(kids) - 1)
    maxh = max(k["h"] for k in kids)
    leaves, groups = {}, []
    x = MARG_X
    for k in kids:
        _place(k, x, (maxh - k["h"]) / 2, [], leaves, groups)
        x += k["w"] + GAP_TOP
    return {"leaves": leaves, "groups": groups, "W": total + 2 * MARG_X, "H": maxh}


def component_boundaries(cfg):
    lay = layout_tree(cfg)
    return {n: r["path"] for n, r in lay["leaves"].items()}


def third_party_components(cfg):
    lay = layout_tree(cfg)
    kinds = {g["name"]: g["kind"] for g in lay["groups"]}
    return {n for n, r in lay["leaves"].items() if any(kinds.get(p) == "third_party" for p in r["path"])}


def _is_third_party(cfg, comp):
    return comp["name"] in third_party_components(cfg)


def flow_crossings(cfg):
    """{flow_key: [boundary names crossed]} — a boundary is crossed when exactly one endpoint is inside it."""
    paths = component_boundaries(cfg)
    out = {}
    for f in cfg["scenario"]["data_flows"]:
        a, b = set(paths.get(f["source"], [])), set(paths.get(f["destination"], []))
        out[_flow_key(f)] = sorted(a ^ b, key=lambda n: (-len(n), n))
    return out


# ── geometry helpers ─────────────────────────────────────────────────────────────────────────
def _exit_rect(r, ox, oy, tx, ty):
    dx, dy = tx - ox, ty - oy
    ts = []
    if dx > 1e-9:
        ts.append((r["x"] + r["w"] - ox) / dx)
    elif dx < -1e-9:
        ts.append((r["x"] - ox) / dx)
    if dy > 1e-9:
        ts.append((r["y"] + r["h"] - oy) / dy)
    elif dy < -1e-9:
        ts.append((r["y"] - oy) / dy)
    t = min([x for x in ts if x > 0] or [0])
    return ox + dx * t, oy + dy * t


def _quad_pts(p1, c, p2, n=20):
    return [((1 - t) ** 2 * p1[0] + 2 * (1 - t) * t * c[0] + t * t * p2[0],
             (1 - t) ** 2 * p1[1] + 2 * (1 - t) * t * c[1] + t * t * p2[1]) for t in [i / n for i in range(n + 1)]]


def _inside(p, r, m=0):
    return r["x"] - m <= p[0] <= r["x"] + r["w"] + m and r["y"] - m <= p[1] <= r["y"] + r["h"] + m


def _route(a, b, off, obstacles):
    ax, ay, bx, by = a["cx"], a["cy"], b["cx"], b["cy"]
    dx, dy = bx - ax, by - ay
    L = math.hypot(dx, dy) or 1.0
    nx, ny = -dy / L, dx / L
    ax, ay, bx, by = ax + nx * off, ay + ny * off, bx + nx * off, by + ny * off
    first = None
    for bow in (0, 64, -64, 110, -110, 160, -160):
        cx_, cy_ = (ax + bx) / 2 + nx * bow, (ay + by) / 2 + ny * bow
        p1 = _exit_rect(a, ax, ay, cx_, cy_)
        p2 = _exit_rect(b, bx, by, cx_, cy_)
        pts = _quad_pts(p1, (cx_, cy_), p2)
        cand = (p1, (cx_, cy_), p2, pts)
        if first is None:
            first = cand
        if not any(_inside(p, o, 8) for p in pts[2:-2] for o in obstacles):
            return cand
    return first


def _route_actor(start, rect, obstacles):
    sx, sy = start
    tx, ty = rect["cx"], rect["cy"]
    dx, dy = tx - sx, ty - sy
    L = math.hypot(dx, dy) or 1.0
    nx, ny = -dy / L, dx / L
    first = None
    for bow in (0, 90, -90, 150, -150, 210, -210):
        cx_, cy_ = (sx + tx) / 2 + nx * bow, (sy + ty) / 2 + ny * bow
        end = _exit_rect(rect, tx, ty, cx_, cy_)
        pts = _quad_pts(start, (cx_, cy_), end)
        cand = (start, (cx_, cy_), end)
        if first is None:
            first = cand
        if not any(_inside(q, o, 6) for q in pts[1:-2] for o in obstacles):
            return cand
    return first


def _devil_svg(cx, cy, tip=""):
    t = f"<title>{_xml(tip)}</title>" if tip else ""
    return (f'<g transform="translate({cx:.1f},{cy:.1f})">{t}'
            '<path d="M-15,-9 L-23,-28 L-6,-18 Z" fill="#35332E"/><path d="M15,-9 L23,-28 L6,-18 Z" fill="#35332E"/>'
            '<circle r="19" fill="white" stroke="#35332E" stroke-width="2.6"/>'
            '<circle cx="-6.5" cy="-3" r="2.6" fill="#35332E"/><circle cx="6.5" cy="-3" r="2.6" fill="#35332E"/>'
            '<path d="M-12,-10 L-3,-6.5 M12,-10 L3,-6.5" stroke="#35332E" stroke-width="2" stroke-linecap="round" fill="none"/>'
            '<path d="M-9,6 Q0,15 9,6" fill="none" stroke="#35332E" stroke-width="2.4" stroke-linecap="round"/></g>')


def _badge_w(code, kind=None):
    return max(32, 7.2 * len(code) + 12)


def _badge_svg(x, y, code, kind, tip="", h=18):
    k = ANNOTATION_KINDS[kind]
    w = _badge_w(code, kind)
    t = f"<title>{_xml(tip)}</title>" if tip else ""
    return (f'<g>{t}<rect x="{x:.1f}" y="{y - h / 2:.1f}" width="{w:.1f}" height="{h}" rx="2" fill="{k["fill"]}" stroke="{k["stroke"]}" stroke-width="1.4"/>'
            f'<text x="{x + w / 2:.1f}" y="{y + 3.6:.1f}" text-anchor="middle" class="t-badge" fill="{k["text"]}">{_xml(code)}</text></g>')


def _item_tip(it):
    k = ANNOTATION_KINDS[it["kind"]]
    tip = f"{it['id']} · {k['title']}: {it['label']}"
    if it.get("stride"):
        tip += f" [{STRIDE_NAMES.get(it['stride'], it['stride'])}]"
    if it.get("capability"):
        tip += f" (capability: {it['capability']})"
    if it.get("notes"):
        tip += f" — {it['notes']}"
    if it.get("links"):
        tip += f" (linked: {', '.join(it['links'])})"
    return tip


def _actor_targets(a):
    return [a["target"]] + [e for e in a.get("entries", []) if e != a["target"]]


# ═════════════════════════════════════════════════════════════════════════════════════════════
#  RENDERER
#  modes: architecture · dfd · boundaries · actors · stride · mitre · zonerules · threat · zones ·
#         scope · scoring · controls · residual
# ═════════════════════════════════════════════════════════════════════════════════════════════
TRUST_MODES = ("boundaries", "actors", "stride", "mitre", "threat", "zonerules")
ID_MODES = ("dfd", "boundaries", "actors", "stride", "mitre")
MODE_TITLES = {
    "architecture": "Architecture: what runs where", "dfd": "Data-flow diagram (DFD)", "boundaries": "Trust boundaries",
    "actors": "Threat actors and entry points", "stride": "STRIDE mapping aligned to the architecture",
    "mitre": "MITRE ATT&CK mapping", "zonerules": "Zone-direction rules (STRIDE hints)", "threat": "Threat impact map",
    "zones": "Zones of trust", "scope": "Scope view: in scope vs out of scope", "scoring": "Inherent risk heat map",
    "controls": "Controls applied to risks", "residual": "Residual risk heat map",
}


def render_architecture_svg(workshop_config, highlighted_threats=None, mode="architecture", annotations=None,
                            out_of_scope=(), risk_map=None, ctrl_map=None, stride_map=None, mitre_map=None):
    highlighted_threats = highlighted_threats or []
    annotations = annotations or []
    oos = set(out_of_scope or ())
    risk_map, ctrl_map = risk_map or {}, ctrl_map or {}
    stride_map, mitre_map = stride_map or {}, mitre_map or {}
    heat = mode in ("scoring", "controls", "residual")
    scn = workshop_config["scenario"]
    comps, flows = scn["components"], scn["data_flows"]
    cmap = {c["name"]: c for c in comps}
    eid = element_ids(scn)
    third = third_party_components(workshop_config)
    crossings = flow_crossings(workshop_config)
    lay = layout_tree(workshop_config)
    leaves, groups = lay["leaves"], lay["groups"]

    show_groups = mode != "dfd"
    trust_mode = mode in TRUST_MODES
    show_ids = mode in ID_MODES
    dfd_shapes = mode == "dfd"
    actors = [a for a in annotations if a["kind"] == "actor"] if mode not in ("dfd",) else []
    others = [a for a in annotations if a["kind"] != "actor"] if mode != "dfd" else []
    by_target = {}
    for it in others:
        by_target.setdefault(it.get("target"), []).append(it)

    W = max(1000, lay["W"])
    shift_x = (W - lay["W"]) / 2
    rows_needed = 0
    if actors:
        per_row = max(1, int((W - 120) // 190))
        rows_needed = min(3, math.ceil(len(actors) / per_row))
    actor_band = (rows_needed * 118 + 26) if actors else 0
    oy = _TOP + actor_band + 18
    for r in list(leaves.values()) + groups:
        r["x"] += shift_x
        r["cx"] = r.get("cx", 0) + (shift_x if "cx" in r else 0)
        r["y"] += oy
        if "cy" in r:
            r["cy"] += oy
    diagram_bottom = oy + lay["H"]

    threat_nodes, threat_flows = set(), set()
    for t in highlighted_threats:
        c = t.get("component", "")
        (threat_flows if "→" in c else threat_nodes).add(c)

    # ── edges ────────────────────────────────────────────────────────────────────────────
    pair_n, pair_seen = {}, {}
    for f in flows:
        k = tuple(sorted([f["source"], f["destination"]]))
        pair_n[k] = pair_n.get(k, 0) + 1
    edges = []
    for f in flows:
        src, dst = f["source"], f["destination"]
        if src not in leaves or dst not in leaves:
            continue
        pk = tuple(sorted([src, dst]))
        oi = pair_seen.get(pk, 0)
        pair_seen[pk] = oi + 1
        off = (oi - (pair_n[pk] - 1) / 2) * 16
        obstacles = [r for n, r in leaves.items() if n not in (src, dst)]
        p1, c, p2, pts = _route(leaves[src], leaves[dst], off, obstacles)
        key = _flow_key(f)
        mid = ((p1[0] + 2 * c[0] + p2[0]) / 4, (p1[1] + 2 * c[1] + p2[1]) / 4)
        edges.append({"f": f, "key": key, "p1": p1, "c": c, "p2": p2, "pts": pts, "mid": mid, "crossed": crossings.get(key, [])})
    flow_mid = {e["key"]: e["mid"] for e in edges}

    s = []
    # canvas size is finalised after registers/legend are measured; placeholder replaced at the end
    s.append("@@SVGOPEN@@")
    s.append(f"""<defs><style>
.t-title{{font:700 14px {_FONT};fill:#1D1C1A}}
.t-mode{{font:500 10.5px {_FONT};fill:#948D80}}
.t-gt{{font:700 11.5px {_FONT};fill:#35332E}}
.t-gs{{font:italic 500 9px {_FONT};fill:#948D80}}
.t-name{{font:700 11.5px {_FONT};fill:#2E2C28}}
.t-desc{{font:400 8.6px {_FONT};fill:#6F6A5F}}
.t-edge{{font:500 9px {_FONT}}}
.t-badge{{font:700 9.5px {_MONO}}}
.t-zone{{font:600 8.5px {_MONO};fill:white}}
.t-id{{font:700 8.5px {_MONO};fill:#5B574E}}
.t-leg{{font:400 9px {_FONT};fill:#5B574E}}
.t-legt{{font:700 9.5px {_FONT};fill:#35332E}}
.t-reg{{font:400 9.2px {_FONT};fill:#32302C}}
.t-actor{{font:600 9px {_FONT};fill:#752727}}
</style>
<marker id="mk-n" markerWidth="10" markerHeight="10" refX="9" refY="5" orient="auto"><path d="M1,1 L9,5 L1,9 Z" fill="#48453E"/></marker>
<marker id="mk-r" markerWidth="10" markerHeight="10" refX="9" refY="5" orient="auto"><path d="M1,1 L9,5 L1,9 Z" fill="#B63838"/></marker>
<marker id="mk-a" markerWidth="10" markerHeight="10" refX="9" refY="5" orient="auto"><path d="M1,1 L9,5 L1,9 Z" fill="#CF8E17"/></marker>
<marker id="mk-g" markerWidth="10" markerHeight="10" refX="9" refY="5" orient="auto"><path d="M1,1 L9,5 L1,9 Z" fill="#367539"/></marker>
<marker id="mk-o" markerWidth="10" markerHeight="10" refX="9" refY="5" orient="auto"><path d="M1,1 L9,5 L1,9 Z" fill="#BFBCB6"/></marker>
<marker id="mk-ta" markerWidth="10" markerHeight="10" refX="9" refY="5" orient="auto"><path d="M1,1 L9,5 L1,9 Z" fill="#752727"/></marker>
<filter id="sh" x="-10%" y="-10%" width="120%" height="130%"><feDropShadow dx="0" dy="1.4" stdDeviation="1.8" flood-color="#000" flood-opacity="0.14"/></filter>
</defs>""")
    s.append(f'<rect x="0" y="0" width="{W}" height="@@H@@" fill="white"/>')
    s.append(f'<text x="14" y="21" class="t-title">{_xml(scn.get("title", "System architecture"))}</text>')
    s.append(f'<text x="{W - 14}" y="21" text-anchor="end" class="t-mode">{_xml(MODE_TITLES.get(mode, ""))}</text>')

    # ── trust boundaries / environments ────────────────────────────────────────────────
    if show_groups:
        for g in sorted(groups, key=lambda r: r["depth"]):
            kind_fill = {"third_party": "#FDF9ED", "internet": "#F7F7F6", "cloud": "#FAFAF9"}.get(g["kind"], "#FFFFFF" if g["depth"] else "#FDFDFC")
            dash = ' stroke-dasharray="9,5"' if trust_mode else ""
            stroke = "#843434" if (trust_mode and g["kind"] == "internet") else "#35332E"
            sw = 1.9 if g["depth"] == 0 else 1.5
            s.append(f'<rect x="{g["x"]:.1f}" y="{g["y"]:.1f}" width="{g["w"]:.1f}" height="{g["h"]:.1f}" rx="18" fill="{kind_fill}" stroke="{stroke}" stroke-width="{sw}"{dash}><title>{_xml(g["name"])} — {_xml(g["trust"] or "environment")}</title></rect>')
            s.append(f'<text x="{g["x"] + 14:.1f}" y="{g["y"] + 20:.1f}" class="t-gt">{_xml(g["name"])}</text>')
            if g["trust"] and mode != "architecture":
                s.append(f'<text x="{g["x"] + g["w"] - 14:.1f}" y="{g["y"] + 20:.1f}" text-anchor="end" class="t-gs">{_xml(g["trust"])}</text>')

    # ── edges ──────────────────────────────────────────────────────────────────────────
    zsc = {c["name"]: c.get("zone_score", 3) for c in comps}
    label_items = []
    for e in edges:
        f, key = e["f"], e["key"]
        src, dst = f["source"], f["destination"]
        is_thr = key in threat_flows
        crossing = bool(e["crossed"])
        col, mk, sw, dash = "#48453E", "mk-n", 1.8, ""
        if trust_mode and crossing:
            col, mk, sw, dash = "#A82B2B", "mk-r", 2.1, ' stroke-dasharray="7,4"'
        if is_thr:
            col, mk, sw = "#B63838", "mk-r", 2.8
        xb = []
        if heat and key in risk_map:
            band = risk_band(risk_map[key])
            col, mk, sw, dash = BAND_COLORS[band][1], {"High": "mk-r", "Medium": "mk-a", "Low": "mk-g"}[band], 3, ""
            xb.append(("risk", (f"R{risk_map[key]}", band), 30))
            if mode == "controls" and ctrl_map.get(key):
                xb.append(("ctl", ctrl_map[key], 30))
        if src in oos or dst in oos:
            col, mk, sw, dash = "#BFBCB6", "mk-o", 1.3, ' stroke-dasharray="3,4"'
        d = f'M{e["p1"][0]:.1f},{e["p1"][1]:.1f} Q{e["c"][0]:.1f},{e["c"][1]:.1f} {e["p2"][0]:.1f},{e["p2"][1]:.1f}'
        s.append(f'<path d="{d}" fill="none" stroke="{col}" stroke-width="{sw}"{dash} marker-end="url(#{mk})"/>')
        tags = []
        if mode == "zonerules":
            sz, dz = zsc.get(src, 3), zsc.get(dst, 3)
            if sz < dz: tags.append("T")
            if sz > dz: tags.append("I")
            if sz == 0: tags.append("D")
        if mode in ("stride", "mitre"):
            tags += [ch for ch in stride_map.get(key, []) if ch in STRIDE_LETTERS]
        if mode == "mitre":
            for tid in mitre_map.get(key, [])[:3]:
                xb.append(("mitre", tid, 40))
        label_items.append({"key": key, "mid": e["mid"], "col": col, "tags": tags, "xb": xb, "crossed": e["crossed"],
                            "data": f.get("data", "") or "", "proto": f.get("protocol", "")})

    # crossing markers
    if trust_mode:
        gmap = {g["name"]: g for g in groups}
        for e in edges:
            for gname in e["crossed"]:
                g = gmap.get(gname)
                if not g:
                    continue
                st_ = [_inside(p, g) for p in e["pts"]]
                for i in range(1, len(st_)):
                    if st_[i] != st_[i - 1]:
                        mx = (e["pts"][i][0] + e["pts"][i - 1][0]) / 2
                        my = (e["pts"][i][1] + e["pts"][i - 1][1]) / 2
                        s.append(f'<g><title>{_xml(e["key"])} crosses {_xml(gname)}</title><circle cx="{mx:.1f}" cy="{my:.1f}" r="5.5" fill="white" stroke="#A82B2B" stroke-width="2"/>'
                                 f'<circle cx="{mx:.1f}" cy="{my:.1f}" r="1.8" fill="#A82B2B"/></g>')
                        break

    # ── nodes ──────────────────────────────────────────────────────────────────────────
    for comp in comps:
        name = comp["name"]
        if name not in leaves:
            continue
        r = leaves[name]
        ctype = comp.get("type", "process")
        zone = comp.get("zone", "Standard Application")
        zs = _ZONE_STYLE.get(zone, _ZONE_STYLE["Standard Application"])
        is_thr = name in threat_nodes
        in_oos = name in oos
        r_here = risk_map.get(name) if heat else None
        x0, y0, w, h = r["x"], r["y"], r["w"], r["h"]
        cx, cy = r["cx"], r["cy"]
        tp = name in third
        if dfd_shapes:
            fill = "#EFEFEE" if ctype == "external_entity" else "white"
            stroke, dark = "#32302C", True
        else:
            if ctype == "datastore":
                fill, stroke, dark = "#374D74", "#20304D", False
            elif ctype == "external_entity":
                fill, stroke, dark = ("#FAF0D1", "#A77F1C", True) if tp else ("#F0F0EF", "#53719C", True)
            else:
                fill, stroke, dark = "#D8E4C8", "#5B7440", True
        swn = 1.9
        if mode == "zones":
            fill, stroke, dark = zs["band"], zs["stroke"], True
        if is_thr:
            fill, stroke, swn, dark = "#FAD2D6", "#B63838", 3, True
        if r_here:
            fill, stroke, swn, dark = BAND_COLORS[risk_band(r_here)][0], BAND_COLORS[risk_band(r_here)][1], 3, True
        if in_oos:
            fill, stroke, swn, dark = "#EFEFEE", "#A7A297", 1.5, True
        sd = ' stroke-dasharray="5,3"' if in_oos else ""
        tcol = "#A7A297" if in_oos else ("#2E2C28" if dark else "#FFFFFF")
        dcol = "#A7A297" if in_oos else ("#6F6A5F" if dark else "#EAE9E7")
        tip = f"<title>{_xml(name)} — {_xml(comp.get('description', ''))} · {_xml(zone)} (Z{comp.get('zone_score', 0)})</title>"
        if dfd_shapes and ctype == "process":
            s.append(f'<g filter="url(#sh)">{tip}<ellipse cx="{cx}" cy="{cy}" rx="{w / 2}" ry="{h / 2 + 2}" fill="{fill}" stroke="{stroke}" stroke-width="{swn}"{sd}/></g>')
        elif dfd_shapes and ctype == "datastore":
            s.append(f'<g>{tip}<rect x="{x0}" y="{y0 + 4}" width="{w}" height="{h - 8}" fill="{fill}" stroke="none"/>'
                     f'<line x1="{x0}" y1="{y0 + 4}" x2="{x0 + w}" y2="{y0 + 4}" stroke="{stroke}" stroke-width="2.4"/>'
                     f'<line x1="{x0}" y1="{y0 + h - 4}" x2="{x0 + w}" y2="{y0 + h - 4}" stroke="{stroke}" stroke-width="2.4"/></g>')
        elif dfd_shapes:
            s.append(f'<g filter="url(#sh)">{tip}<rect x="{x0}" y="{y0}" width="{w}" height="{h}" rx="2" fill="{fill}" stroke="{stroke}" stroke-width="{swn}"{sd}/></g>')
        elif ctype == "datastore":
            cap = 9
            body = f'M{x0},{y0 + cap} L{x0},{y0 + h - cap} A{w / 2},{cap} 0 0 0 {x0 + w},{y0 + h - cap} L{x0 + w},{y0 + cap} Z'
            s.append(f'<g filter="url(#sh)">{tip}<path d="{body}" fill="{fill}" stroke="{stroke}" stroke-width="{swn}"{sd}/>'
                     f'<ellipse cx="{cx}" cy="{y0 + cap}" rx="{w / 2}" ry="{cap}" fill="{fill}" stroke="{stroke}" stroke-width="{swn}"{sd}/>'
                     f'<path d="M{x0 + 1},{y0 + cap + 9} A{w / 2 - 1},{cap} 0 0 0 {x0 + w - 1},{y0 + cap + 9}" fill="none" stroke="{"#A5B6D4" if not dark else stroke}" stroke-width="0.8" opacity="0.7"/></g>')
        else:
            rx = 9 if ctype != "external_entity" else 14
            s.append(f'<g filter="url(#sh)">{tip}<rect x="{x0}" y="{y0}" width="{w}" height="{h}" rx="{rx}" fill="{fill}" stroke="{stroke}" stroke-width="{swn}"{sd}/></g>')
        desc = zone if mode == "zones" else comp.get("description", "")
        yb = cy + (7 if ctype == "datastore" else 0)
        s.append(f'<text x="{cx}" y="{yb - 2}" text-anchor="middle" class="t-name" style="fill:{tcol}">{_xml(_trunc(name, 22))}</text>')
        s.append(f'<text x="{cx}" y="{yb + 11}" text-anchor="middle" class="t-desc" style="fill:{dcol}">{_xml(_trunc(desc, 32))}</text>')
        if show_ids:
            s.append(f'<text x="{x0 + 6}" y="{y0 + 11}" class="t-id">{eid.get(name, "")}</text>')
        if mode not in ("dfd", "architecture"):
            s.append(f'<rect x="{cx - 16}" y="{y0 + h - 7}" width="32" height="14" rx="7" fill="{zs["stroke"]}"/>'
                     f'<text x="{cx}" y="{y0 + h + 3}" text-anchor="middle" class="t-zone">Z{_xml(comp.get("zone_score", 0))}</text>')
        if is_thr:
            s.append(f'<circle cx="{x0 + w}" cy="{y0}" r="9" fill="#B63838"/><text x="{x0 + w}" y="{y0 + 4}" text-anchor="middle" font-family="Arial" font-size="12" font-weight="700" fill="white">!</text>')
        if in_oos:
            s.append(f'<rect x="{x0 + w - 78}" y="{y0 - 8}" width="78" height="15" rx="7" fill="#948D80"/>'
                     f'<text x="{x0 + w - 39}" y="{y0 + 2.5}" text-anchor="middle" class="t-zone">OUT OF SCOPE</text>')
        if r_here:
            rs = BAND_COLORS[risk_band(r_here)][1]
            s.append(f'<g><title>Risk score {r_here} ({risk_band(r_here)})</title><rect x="{x0 + w - 30}" y="{y0 - 9}" width="34" height="18" rx="7" fill="{rs}"/>'
                     f'<text x="{x0 + w - 13}" y="{y0 + 3.5}" text-anchor="middle" class="t-zone">R{r_here}</text></g>')
            if mode == "controls" and ctrl_map.get(name):
                s.append(f'<g><title>{ctrl_map[name]} control(s) selected</title><rect x="{x0 + w - 66}" y="{y0 - 9}" width="32" height="18" rx="7" fill="#367539"/>'
                         f'<text x="{x0 + w - 50}" y="{y0 + 3.5}" text-anchor="middle" class="t-zone">C×{ctrl_map[name]}</text></g>')
        # STRIDE chips and ATT&CK pills under the node
        below = y0 + h + 16
        if mode in ("stride", "mitre"):
            letters = [ch for ch in stride_map.get(name, []) if ch in STRIDE_LETTERS]
            if letters:
                bx = cx - (len(letters) * 18 - 2) / 2
                for ch in letters:
                    s.append(f'<g><title>{STRIDE_NAMES[ch]}</title><rect x="{bx:.1f}" y="{below - 8:.1f}" width="16" height="16" rx="3" fill="{_STRIDE_TAG_COLOR[ch]}"/>'
                             f'<text x="{bx + 8:.1f}" y="{below + 3.6:.1f}" text-anchor="middle" class="t-badge" fill="white">{ch}</text></g>')
                    bx += 18
                below += 19
        if mode == "mitre":
            ids = mitre_map.get(name, [])
            if ids:
                shown = ids[:3]
                pill_w = 44
                bx = cx - (len(shown) * (pill_w + 3) - 3) / 2
                for tid in shown:
                    s.append(f'<g><title>ATT&amp;CK {_xml(tid)}</title><rect x="{bx:.1f}" y="{below - 8:.1f}" width="{pill_w}" height="15" rx="7" fill="#4B3394"/>'
                             f'<text x="{bx + pill_w / 2:.1f}" y="{below + 2.8:.1f}" text-anchor="middle" class="t-zone">{_xml(tid)}</text></g>')
                    bx += pill_w + 3
        # learner labels (assets / threat scenarios / controls) in a row above the node
        items = sorted(by_target.get(name, []), key=_ann_sort)
        if items:
            bx0, row = x0, 0
            bx = bx0
            for it in items:
                bw = _badge_w(it["id"])
                if bx > bx0 and bx + bw > x0 + w + 40:
                    bx, row = bx0, row + 1
                s.append(_badge_svg(bx, y0 - 14 - row * 22, it["id"], it["kind"], _item_tip(it)))
                bx += bw + 4

    # ── flow labels + their extras ─────────────────────────────────────────────────────
    placed = []

    def _free(box):
        return not any(box[0] < q[2] + 3 and box[2] > q[0] - 3 and box[1] < q[3] + 3 and box[3] > q[1] - 3 for q in placed)

    node_rects = [(r["x"], r["y"], r["x"] + r["w"], r["y"] + r["h"]) for r in leaves.values()]
    done_keys = set()
    for L in label_items:
        key, (lx, ly) = L["key"], L["mid"]
        base = L["data"]
        txt = _trunc((f"{eid.get(key, '')} · " if show_ids else "") + base, 28)
        lw = len(txt) * 5.3 + 12 if txt else 0
        extras = [("chip", tg, 16) for tg in L["tags"]]
        for kind_, val, wd in L["xb"]:
            extras.append((kind_, val, wd))
        if key not in done_keys:
            done_keys.add(key)
            for it in sorted(by_target.get(key, []), key=_ann_sort):
                extras.append(("ann", it, _badge_w(it["id"])))
        total = sum(e[2] for e in extras) + 4 * max(0, len(extras) - 1)
        dy_choice = 0
        for cand in (0, -20, 20, -40, 40, -60, 60):
            ty = ly + cand
            box = [min(lx - lw / 2, lx - total / 2 if extras else 1e9), ty - 10, max(lx + lw / 2, lx + total / 2 if extras else -1e9),
                   ty + (24 if extras else 7)]
            hit_node = any(box[0] < n[2] and box[2] > n[0] and box[1] < n[3] and box[3] > n[1] for n in node_rects)
            if _free(box) and not hit_node:
                dy_choice = cand
                break
            dy_choice = cand if cand == 0 else dy_choice
        ty = ly + dy_choice
        placed.append([min(lx - lw / 2, lx - total / 2 if extras else 1e9), ty - 10, max(lx + lw / 2, lx + total / 2 if extras else -1e9),
                       ty + (24 if extras else 7)])
        L["anchor"] = (lx, ty)
        if txt:
            tip = f"{key} · {base}" + (f" · {L['proto']}" if L["proto"] else "") + (f" · crosses: {', '.join(L['crossed'])}" if L["crossed"] else "")
            s.append(f'<g><title>{_xml(tip)}</title><rect x="{lx - lw / 2:.1f}" y="{ty - 9:.1f}" width="{lw:.1f}" height="14" rx="4" fill="white" stroke="#D8D6D3" stroke-width="0.8"/>'
                     f'<text x="{lx:.1f}" y="{ty + 1:.1f}" text-anchor="middle" class="t-edge" fill="{L["col"]}">{_xml(txt)}</text></g>')
        bx, by = lx - total / 2, ty + 19
        for typ, obj, wd in extras:
            if typ == "risk":
                rs = BAND_COLORS[obj[1]][1]
                s.append(f'<g><title>Risk score {obj[0][1:]} ({obj[1]})</title><rect x="{bx:.1f}" y="{by - 8:.1f}" width="30" height="16" rx="6" fill="{rs}"/>'
                         f'<text x="{bx + 15:.1f}" y="{by + 3.5:.1f}" text-anchor="middle" class="t-zone">{obj[0]}</text></g>')
            elif typ == "ctl":
                s.append(f'<g><title>{obj} control(s) selected</title><rect x="{bx:.1f}" y="{by - 8:.1f}" width="30" height="16" rx="6" fill="#367539"/>'
                         f'<text x="{bx + 15:.1f}" y="{by + 3.5:.1f}" text-anchor="middle" class="t-zone">C×{obj}</text></g>')
            elif typ == "mitre":
                s.append(f'<g><title>ATT&amp;CK {_xml(obj)}</title><rect x="{bx:.1f}" y="{by - 8:.1f}" width="40" height="15" rx="7" fill="#4B3394"/>'
                         f'<text x="{bx + 20:.1f}" y="{by + 2.8:.1f}" text-anchor="middle" class="t-zone">{_xml(obj)}</text></g>')
            elif typ == "chip":
                s.append(f'<g><title>{STRIDE_NAMES.get(obj, obj)}</title><rect x="{bx:.1f}" y="{by - 8:.1f}" width="16" height="16" rx="3" fill="{_STRIDE_TAG_COLOR.get(obj, "#555")}"/>'
                         f'<text x="{bx + 8:.1f}" y="{by + 3.6:.1f}" text-anchor="middle" class="t-badge" fill="white">{obj}</text></g>')
            else:
                s.append(_badge_svg(round(bx, 1), round(by, 1), obj["id"], obj["kind"], _item_tip(obj)))
            bx += wd + 4
    flow_anchor = {L["key"]: L["anchor"] for L in label_items}

    # ── threat actors band ─────────────────────────────────────────────────────────────
    if actors:
        def anchor_x(a):
            xs = []
            for t_ in _actor_targets(a):
                if t_ in leaves:
                    xs.append(leaves[t_]["cx"])
                elif t_ in flow_anchor:
                    xs.append(flow_anchor[t_][0])
            return sum(xs) / len(xs) if xs else W / 2
        order = sorted(actors, key=anchor_x)
        row, prev = 0, -1e9
        pos = {}
        for a in order:
            x = max(anchor_x(a), prev + 190, 70)
            if x > W - 110 and row < rows_needed - 1:
                row, prev = row + 1, -1e9
                x = max(anchor_x(a), 70)
            pos[a["id"]] = (min(x, W - 120), _TOP + 46 + row * 118)
            prev = x
        for a in order:
            ax, ay = pos[a["id"]]
            for t_ in _actor_targets(a):
                if t_ in leaves:
                    others_ = [q for n_, q in leaves.items() if n_ != t_]
                    p1, c_, p2 = _route_actor((ax, ay + 24), leaves[t_], others_)
                elif t_ in flow_anchor:
                    p1, p2 = (ax, ay + 24), (flow_anchor[t_][0], flow_anchor[t_][1] - 10)
                    c_ = ((p1[0] + p2[0]) / 2, (p1[1] + p2[1]) / 2)
                else:
                    continue
                s.append(f'<path d="M{p1[0]:.1f},{p1[1]:.1f} Q{c_[0]:.1f},{c_[1]:.1f} {p2[0]:.1f},{p2[1]:.1f}" stroke="#752727" stroke-width="2" fill="none" marker-end="url(#mk-ta)"><title>{_xml(a["id"])} → {_xml(t_)}</title></path>')
        for a in order:
            ax, ay = pos[a["id"]]
            s.append(_devil_svg(ax, ay, _item_tip(a)))
            s.append(f'<text x="{ax:.1f}" y="{ay + 40:.1f}" text-anchor="middle" class="t-actor">{_xml(_trunc(a["label"], 30))}</text>')
            tx, ty = ax + 30, ay - 30
            s.append(_badge_svg(tx, ty, a["id"], "actor", _item_tip(a), h=20))
            ts_ = [t for t in others if t["kind"] == "threat" and a["id"] in t.get("links", [])]
            for i, t in enumerate(ts_[:3]):
                s.append(_badge_svg(tx, ty + 22 * (i + 1), t["id"], "threat", _item_tip(t), h=20))
            if len(ts_) > 3:
                s.append(f'<text x="{tx:.1f}" y="{ty + 22 * 4 + 4:.1f}" class="t-leg">+{len(ts_) - 3} more</text>')

    # ── registers (assets / actors / scenarios / controls), as in the reference style ──
    y_cursor = diagram_bottom + 22
    reg_groups = [(k, [i for i in sorted(annotations, key=_ann_sort) if i["kind"] == k]) for k in ("asset", "actor", "threat", "control")]
    reg_groups = [(k, v) for k, v in reg_groups if v] if mode != "dfd" else []
    if reg_groups:
        n = len(reg_groups)
        gap = 14
        bw = (W - 2 * 14 - gap * (n - 1)) / n
        maxlines = min(8, max(len(v) for _, v in reg_groups))
        bh = 28 + maxlines * 14 + 8
        titles = {"asset": "Assets", "actor": "Threat actors", "threat": "Threat scenarios", "control": "Controls / mitigations"}
        for idx, (k, v) in enumerate(reg_groups):
            x = 14 + idx * (bw + gap)
            kk = ANNOTATION_KINDS[k]
            s.append(f'<rect x="{x:.1f}" y="{y_cursor:.1f}" width="{bw:.1f}" height="{bh}" rx="3" fill="white" stroke="#35332E" stroke-width="1.4"/>')
            s.append(f'<rect x="{x:.1f}" y="{y_cursor:.1f}" width="{bw:.1f}" height="20" rx="3" fill="{kk["fill"]}" opacity="0.35"/>')
            s.append(f'<text x="{x + 8:.1f}" y="{y_cursor + 14:.1f}" class="t-legt">{titles[k]}</text>')
            for i, it in enumerate(v[:8]):
                lab = _trunc(it["label"], int(bw / 5.4) - len(it["id"]) - 3 - (6 if it.get("stride") else 0))
                pre = f"[{it['stride']}] " if it.get("stride") else ""
                s.append(f'<text x="{x + 8:.1f}" y="{y_cursor + 36 + i * 14:.1f}" class="t-reg"><tspan font-weight="700">{_xml(it["id"])}</tspan>: {_xml(pre + lab)}</text>')
            if len(v) > 8:
                s.append(f'<text x="{x + bw - 8:.1f}" y="{y_cursor + bh - 6:.1f}" text-anchor="end" class="t-leg">+{len(v) - 8} more</text>')
        y_cursor += bh + 16

    # ── symbol legend ──────────────────────────────────────────────────────────────────
    leg_y = y_cursor
    s.append(f'<rect x="0" y="{leg_y:.1f}" width="{W}" height="@@LEG@@" fill="#FAFAF9"/><line x1="0" y1="{leg_y:.1f}" x2="{W}" y2="{leg_y:.1f}" stroke="#E9E8E6"/>')
    s.append(f'<text x="14" y="{leg_y + 15:.1f}" class="t-legt">LEGEND</text>')

    def ic_shape_proc(x, y):
        if dfd_shapes:
            return f'<ellipse cx="{x + 10}" cy="{y}" rx="10" ry="6" fill="white" stroke="#32302C" stroke-width="1.3"/>', 20
        return f'<rect x="{x}" y="{y - 6}" width="20" height="12" rx="3" fill="#D8E4C8" stroke="#5B7440" stroke-width="1.3"/>', 20

    def ic_shape_ext(x, y):
        if dfd_shapes:
            return f'<rect x="{x}" y="{y - 6}" width="20" height="12" fill="#EFEFEE" stroke="#32302C" stroke-width="1.3"/>', 20
        return f'<rect x="{x}" y="{y - 6}" width="20" height="12" rx="5" fill="#F0F0EF" stroke="#53719C" stroke-width="1.3"/>', 20

    def ic_shape_ds(x, y):
        if dfd_shapes:
            return f'<line x1="{x}" y1="{y - 5}" x2="{x + 20}" y2="{y - 5}" stroke="#32302C" stroke-width="2"/><line x1="{x}" y1="{y + 5}" x2="{x + 20}" y2="{y + 5}" stroke="#32302C" stroke-width="2"/>', 20
        return (f'<path d="M{x},{y - 3} L{x},{y + 4} A10,3 0 0 0 {x + 20},{y + 4} L{x + 20},{y - 3} Z" fill="#374D74" stroke="#20304D"/>'
                f'<ellipse cx="{x + 10}" cy="{y - 3}" rx="10" ry="3" fill="#374D74" stroke="#20304D"/>'), 20

    def ic_boundary(x, y):
        return f'<rect x="{x}" y="{y - 6}" width="22" height="12" rx="5" fill="none" stroke="#35332E" stroke-width="1.5" stroke-dasharray="4,2"/>', 22

    def ic_cross(x, y):
        return f'<circle cx="{x + 7}" cy="{y}" r="5.5" fill="white" stroke="#A82B2B" stroke-width="2"/><circle cx="{x + 7}" cy="{y}" r="1.8" fill="#A82B2B"/>', 14

    def ic_zone(x, y):
        return f'<rect x="{x}" y="{y - 6}" width="22" height="12" rx="6" fill="#E4A33A"/><text x="{x + 11}" y="{y + 3}" text-anchor="middle" class="t-zone">Z3</text>', 22

    def ic_oos(x, y):
        return f'<rect x="{x}" y="{y - 6}" width="22" height="12" rx="5" fill="#EFEFEE" stroke="#A7A297" stroke-dasharray="3,2"/>', 22

    def ic_risk(band):
        return lambda x, y: (f'<rect x="{x}" y="{y - 7}" width="22" height="14" rx="6" fill="{BAND_COLORS[band][1]}"/>', 22)

    def ic_ctl(x, y):
        return f'<rect x="{x}" y="{y - 7}" width="26" height="14" rx="6" fill="#367539"/><text x="{x + 13}" y="{y + 3}" text-anchor="middle" class="t-zone">C×n</text>', 26

    def ic_stride(x, y):
        return f'<rect x="{x}" y="{y - 8}" width="16" height="16" rx="3" fill="#CF5817"/><text x="{x + 8}" y="{y + 3.6}" text-anchor="middle" class="t-badge" fill="white">T</text>', 16

    def ic_mitre(x, y):
        return f'<rect x="{x}" y="{y - 7}" width="40" height="15" rx="7" fill="#4B3394"/><text x="{x + 20}" y="{y + 3}" text-anchor="middle" class="t-zone">T1190</text>', 40

    def ic_devil(x, y):
        return _devil_svg(x + 9, y + 1).replace('transform="translate(', 'transform="scale(0.45) translate(').replace(f'{x + 9:.1f},{y + 1:.1f})"', f'{(x + 9) / 0.45:.1f},{(y + 1) / 0.45:.1f})"'), 20

    def ic_badge(kind, code):
        return lambda x, y: (_badge_svg(x, y, code, kind, h=16), _badge_w(code))

    def ic_bang(x, y):
        return f'<circle cx="{x + 8}" cy="{y}" r="8" fill="#B63838"/><text x="{x + 8}" y="{y + 4}" text-anchor="middle" font-family="Arial" font-size="11" font-weight="700" fill="white">!</text>', 16

    items = [(ic_shape_ext, "External entity"), (ic_shape_proc, "Process"), (ic_shape_ds, "Data store")]
    if show_groups:
        items.append((ic_boundary, "Trust boundary / environment"))
    if trust_mode:
        items.append((ic_cross, "Boundary crossing"))
    if mode not in ("dfd", "architecture"):
        items.append((ic_zone, "Criticality zone (0–9)"))
    if actors or mode == "actors":
        items.append((ic_devil, "Threat actor → entry point"))
    if mode != "dfd":
        items += [(ic_badge("actor", "TA01"), "Threat actor"), (ic_badge("asset", "A01"), "Asset"),
                  (ic_badge("threat", "TS01"), "Threat scenario"), (ic_badge("control", "C01"), "Control")]
    if mode in ("stride", "mitre"):
        items.append((ic_stride, "STRIDE category (S T R I D E)"))
    if mode == "zonerules":
        items.append((ic_stride, "Zone-rule hint (T / I / D)"))
    if mode == "mitre":
        items.append((ic_mitre, "ATT&CK technique"))
    if threat_nodes or threat_flows:
        items.append((ic_bang, "Threat identified"))
    if oos:
        items.append((ic_oos, "Out of scope"))
    if heat:
        items += [(ic_risk("Low"), "Low risk (1–2)"), (ic_risk("Medium"), "Medium (3–4)"), (ic_risk("High"), "High (6–9)")]
    if mode == "controls":
        items.append((ic_ctl, "Controls selected"))
    lx_, ly_ = 14, leg_y + 34
    for fn, text in items:
        w_item = 34 + len(text) * 5.1
        if lx_ + w_item > W - 10:
            lx_, ly_ = 14, ly_ + 20
        svg_i, iw = fn(lx_, ly_)
        s.append(svg_i)
        s.append(f'<text x="{lx_ + iw + 6}" y="{ly_ + 3}" class="t-leg">{_xml(text)}</text>')
        lx_ += iw + 6 + len(text) * 5.1 + 18
    leg_h = (ly_ - leg_y) + 22
    H = leg_y + leg_h
    out = "\n".join(s).replace("@@H@@", f"{H:.0f}").replace("@@LEG@@", f"{leg_h:.0f}")
    head = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H:.0f}" viewBox="0 0 {W:.0f} {H:.0f}" '
            f'style="width:100%;height:auto;max-width:{W:.0f}px;background:white" role="img">')
    return out.replace("@@SVGOPEN@@", head) + "\n</svg>"


# ═════════════════════════════════════════════════════════════════════════════════════════════
#  DYNAMIC LABELS: threat actors · assets · threat scenarios · controls
# ═════════════════════════════════════════════════════════════════════════════════════════════
def get_annotations(ws_id=None):
    ws_id = ws_id or st.session_state.selected_workshop
    return st.session_state.annotations.setdefault(ws_id, [])


def _next_annotation_id(items, kind):
    pre = ANNOTATION_KINDS[kind]["prefix"]
    nums = [int(re.sub(r"\D", "", i["id"]) or 0) for i in items if i["kind"] == kind]
    return f"{pre}{max(nums, default=0) + 1:02d}"


def annotation_register_df(items):
    rows = []
    for it in sorted(items, key=_ann_sort):
        rows.append({
            "ID": it["id"], "Type": ANNOTATION_KINDS[it["kind"]]["title"], "Label": it["label"],
            "Attached to": ", ".join(_actor_targets(it)) if it["kind"] == "actor" else it["target"],
            "STRIDE": STRIDE_NAMES.get(it.get("stride", ""), ""), "Capability": it.get("capability", ""),
            "Linked to": ", ".join(it.get("links", [])), "Notes": it.get("notes", "")})
    return pd.DataFrame(rows, columns=["ID", "Type", "Label", "Attached to", "STRIDE", "Capability", "Linked to", "Notes"])


def diagram_label_editor(workshop_config, key, default_kind=None):
    ws_id = st.session_state.selected_workshop
    items = get_annotations(ws_id)
    sc = workshop_config["scenario"]
    targets = [c["name"] for c in sc["components"]] + list(dict.fromkeys(_flow_key(f) for f in sc["data_flows"]))
    nonce = st.session_state.annot_nonce
    with st.expander(f"✏️ Label this diagram — threat actors · assets · threat scenarios · controls  ({len(items)} labels)", expanded=False):
        st.caption("Labels appear on every diagram of this lab. Threat actors are drawn outside the system with arrows to their entry points; "
                   "link threat scenarios to actors and assets, and controls to the scenarios they mitigate.")
        c1, c2 = st.columns([1, 2])
        kind = c1.selectbox("Label type", _KIND_ORDER, key=f"{key}_kind",
                            index=_KIND_ORDER.index(default_kind) if default_kind in _KIND_ORDER else 0,
                            format_func=lambda k: f"{ANNOTATION_KINDS[k]['icon']} {ANNOTATION_KINDS[k]['title']}")
        target = c2.selectbox("Attach to (component, entry point or data flow)", targets, key=f"{key}_target_{nonce}")
        extra = {}
        if kind == "actor":
            extra["entries"] = st.multiselect("Additional entry points", [t for t in targets if t != target], key=f"{key}_entries_{nonce}")
            extra["capability"] = st.select_slider("Capability", ["Low", "Medium", "High"], value="Medium", key=f"{key}_cap_{nonce}")
        suggestion = None
        if kind == "asset" and sc.get("assets"):
            pick = st.selectbox("Suggestions from this scenario", ["(type your own)"] + list(sc["assets"]), key=f"{key}_sugg_{nonce}")
            suggestion = None if pick == "(type your own)" else pick
        if kind == "threat":
            sel = st.selectbox("STRIDE category", ["—"] + [f"{k} · {v}" for k, v in STRIDE_NAMES.items()], key=f"{key}_stride_{nonce}")
            extra["stride"] = "" if sel == "—" else sel.split(" · ")[0]
        label = st.text_input("Label", max_chars=80, key=f"{key}_label_{nonce}",
                              placeholder={"actor": "e.g. Adversary with network access", "asset": "e.g. Customer PII",
                                           "threat": "e.g. SQL injection alters order totals", "control": "e.g. Parameterised queries"}[kind])
        link_kinds = {"threat": ["actor", "asset"], "control": ["threat"]}.get(kind, [])
        link_opts = [i for i in sorted(items, key=_ann_sort) if i["kind"] in link_kinds]
        links = []
        if link_opts:
            verb = "Threat actors / assets involved" if kind == "threat" else "Threat scenarios this control mitigates"
            links = st.multiselect(verb, [i["id"] for i in link_opts], key=f"{key}_links_{nonce}",
                                   format_func=lambda cid: f"{cid} — " + next(i["label"] for i in link_opts if i["id"] == cid))
        notes = st.text_input("Notes (optional)", max_chars=160, key=f"{key}_notes_{nonce}")
        if st.button("➕ Add label", key=f"{key}_add", type="primary"):
            final = (label or "").strip() or (suggestion or "")
            if not final:
                st.warning("Enter a label first.")
            else:
                items.append({"id": _next_annotation_id(items, kind), "kind": kind, "label": final, "target": target,
                              "links": links, "notes": (notes or "").strip(), **extra})
                st.session_state.annot_nonce += 1
                save_progress()
                st.rerun()
        if items:
            st.markdown("**Current labels**")
            for it in sorted(items, key=_ann_sort):
                a, b, c, d = st.columns([1, 5, 4, 1])
                a.markdown(f"**{it['id']}**")
                b.text(f"{ANNOTATION_KINDS[it['kind']]['title']}: {it['label']}")
                where = ", ".join(_actor_targets(it)) if it["kind"] == "actor" else it["target"]
                c.text(f"on {where}" + (f"  ↔ {', '.join(it['links'])}" if it.get("links") else ""))
                if d.button("🗑", key=f"{key}_del_{it['id']}", help=f"Remove {it['id']}"):
                    items[:] = [x for x in items if x["id"] != it["id"]]
                    for x in items:
                        x["links"] = [l for l in x.get("links", []) if l != it["id"]]
                    save_progress()
                    st.rerun()
            b1, b2 = st.columns(2)
            b1.download_button("⬇️ Export label register (CSV)", annotation_register_df(items).to_csv(index=False),
                               file_name=f"workshop{ws_id}_labels.csv", mime="text/csv", key=f"{key}_csv", use_container_width=True)
            if b2.button("🧹 Clear all labels", key=f"{key}_clear", use_container_width=True):
                st.session_state.annotations[ws_id] = []
                save_progress()
                st.rerun()


_IFRAME_FONTS = ("<style>@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700"
                 "&family=JetBrains+Mono:wght@500;700&display=swap');body{margin:0;background:transparent}</style>")


def _risk_maps(mode):
    risk, ctrl = {}, {}
    for r in st.session_state.user_answers:
        v = rec_residual(r) if mode == "residual" else rec_risk(r)
        if not v:
            continue
        risk[r["component"]] = max(risk.get(r["component"], 0), v)
        if mode == "controls" and r.get("controlled"):
            ctrl[r["component"]] = ctrl.get(r["component"], 0) + len(r.get("selected_mitigations", []))
    return risk, ctrl


def get_stride_map(ws_id=None):
    ws_id = ws_id or st.session_state.selected_workshop
    return st.session_state.stride_map.setdefault(ws_id, {})


def _mitre_map():
    out = {}
    for r in st.session_state.user_answers:
        for tid in r.get("mitre", []):
            out.setdefault(r["component"], [])
            if tid not in out[r["component"]]:
                out[r["component"]].append(tid)
    return out


DIAGRAM_CAPTIONS = {
    "architecture": "Architecture — boxes group what runs where. Green = process, navy cylinder = data store, blue/yellow = external parties. Hover for details.",
    "dfd":          "Data-flow diagram — rectangles are external entities, ovals are processes, parallel lines are data stores. IDs (E/P/D/F) are used in later steps.",
    "boundaries":   "Trust boundaries — dashed boxes are boundaries; red dashed flows cross at least one boundary (● marks where). Focus your analysis on those flows.",
    "actors":       "Threat actors — devils sit outside the system; arrows show the entry points they can reach. TA = actor, TS = threat scenario linked to them.",
    "stride":       "STRIDE aligned to the architecture — coloured letters are the categories YOU mapped to each element and flow; TA/TS tags show who attacks and how.",
    "mitre":        "MITRE ATT&CK — purple pills are the techniques you mapped to each element, on top of your STRIDE mapping and threat actors.",
    "zonerules":    "Zone-direction hints — T = tampering (low→high zone), I = information disclosure (high→low), D = DoS (Zone-0 source).",
    "threat":       "Threat map — components and flows with identified threats are shown in red.",
    "zones":        "Zones of trust — fill colour = criticality zone of each component.",
    "scope":        "Scope view — grey dashed components are OUT of scope (set them in the scope form above).",
    "scoring":      "Inherent risk — colour = highest risk score (impact × likelihood) on each component or flow.",
    "controls":     "Controls — colour = inherent risk · C×n = number of controls you selected for that component or flow.",
    "residual":     "Residual risk — colour = risk that remains after your controls.",
}


def show_architecture_diagram(workshop_config, threats=None, mode="architecture", key_suffix="", editable=False, default_kind=None):
    ws_id = st.session_state.selected_workshop
    items = get_annotations(ws_id)
    oos = get_scope(ws_id)["oos_components"]
    risk_map, ctrl_map = _risk_maps(mode) if mode in ("scoring", "controls", "residual") else ({}, {})
    smap = get_stride_map(ws_id) if mode in ("stride", "mitre") else {}
    mmap = _mitre_map() if mode == "mitre" else {}
    svg = render_architecture_svg(workshop_config, highlighted_threats=threats or [], mode=mode, annotations=items,
                                  out_of_scope=oos, risk_map=risk_map, ctrl_map=ctrl_map, stride_map=smap, mitre_map=mmap)
    if mode in DIAGRAM_CAPTIONS:
        st.caption("📐 " + DIAGRAM_CAPTIONS[mode])
    m = re.search(r'viewBox="0 0 ([\d.]+) ([\d.]+)"', svg)
    est_h = float(m.group(2)) if m else 600
    components_html.html(
        f'{_IFRAME_FONTS}<div style="overflow-x:auto;border:1px solid #E9E8E7;border-radius:12px;background:white">{svg}</div>',
        height=int(est_h + 30), scrolling=True)
    st.download_button("⬇️ Download diagram (SVG)", svg, file_name=f"workshop{ws_id}_{mode}.svg",
                       mime="image/svg+xml", key=f"dl_svg_{key_suffix}_{mode}")
    if editable:
        diagram_label_editor(workshop_config, key=f"ed_{key_suffix}", default_kind=default_kind)
        if items:
            st.markdown("**Label register**")
            st.dataframe(annotation_register_df(items), hide_index=True, use_container_width=True)
            open_threats = [i["id"] for i in items if i["kind"] == "threat"
                            and not any(c["kind"] == "control" and i["id"] in c.get("links", []) for c in items)]
            if open_threats:
                st.warning(f"Threat scenarios with no linked control yet: {', '.join(open_threats)}")
            elif any(i["kind"] == "threat" for i in items):
                st.success("Every labelled threat scenario has at least one linked control.")


@st.cache_data(show_spinner=False)
def generate_attack_tree(tree_json, title="Attack Tree"):
    tree_structure = json.loads(tree_json)
    """Generate attack tree visualization."""
    try:
        dot = Digraph(comment=title, format="png")
        dot.attr(rankdir="TB", size="16,20", fontname="Arial", bgcolor="white")
        dot.attr("node", fontname="Arial", fontsize="9", shape="box", style="rounded,filled")
        dot.attr("edge", fontname="Arial", fontsize="8")
        counter = [0]

        def add_node(node, parent_id=None):
            counter[0] += 1
            nid = f"n{counter[0]}"
            ntype = node.get("type", "leaf")
            if ntype == "goal":
                fill, shape = "#FBD1D5", "oval"
                lbl = node["label"]
            elif ntype == "and":
                fill, shape = "#C7EFEA", "box"
                lbl = f"{node['label']}\\n[AND – all steps required]"
            elif ntype == "or":
                fill, shape = "#CAE4CB", "box"
                lbl = f"{node['label']}\\n[OR – any path succeeds]"
            else:
                fill, shape = "#FBF5C8", "box"
                diff = node.get("difficulty", "")
                diff_colors = {"Easy": "🔴", "Medium": "🟡", "Hard": "🟢", "Critical": "⚫"}
                lbl = node["label"]
                if diff:
                    lbl += f"\\n{diff_colors.get(diff, '')} {diff}"
            dot.node(nid, lbl, fillcolor=fill, shape=shape)
            if parent_id:
                dot.edge(parent_id, nid)
            for child in node.get("children", []):
                add_node(child, nid)
            return nid

        add_node(tree_structure)
        path = dot.render("attack_tree", format="png", cleanup=True)
        with open(path, "rb") as f:
            return base64.b64encode(f.read()).decode()
    except Exception as e:
        st.error(f"Attack tree error: {e}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# SCORING
# ─────────────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# PERSISTENCE
# ─────────────────────────────────────────────────────────────────────────────
def _progress_path():
    """Per-user progress file, keyed by an id kept in the URL (?sid=...)."""
    sid = st.session_state.get("_sid")
    if not sid:
        try:
            sid = st.query_params.get("sid")
            if isinstance(sid, list):
                sid = sid[0] if sid else None
            if not sid:
                sid = uuid.uuid4().hex[:16]
                st.query_params["sid"] = sid
        except Exception:
            sid = uuid.uuid4().hex[:16]
        sid = re.sub(r"[^A-Za-z0-9]", "", str(sid))[:32] or uuid.uuid4().hex[:16]
        st.session_state["_sid"] = sid
    return os.path.join(tempfile.gettempdir(), f"threat_progress_v4_{sid}.json")


def save_progress():
    """Persist a session atomically; surface failures instead of silently losing work."""
    payload = {
        "schema_version": 2,
        "completed_workshops": list(st.session_state.completed_workshops),
        "unlocked_workshops": list(st.session_state.unlocked_workshops),
        "selected_workshop": st.session_state.selected_workshop,
        "current_step": st.session_state.current_step,
        "threats": st.session_state.threats,
        "user_answers": st.session_state.user_answers,
        "total_score": st.session_state.total_score,
        "max_score": st.session_state.max_score,
        "annotations": st.session_state.annotations,
        "scope_models": st.session_state.scope_models,
        "open_questions": st.session_state.open_questions,
        "review_plans": st.session_state.review_plans,
        "stride_map": st.session_state.stride_map,
        "boundary_checked": st.session_state.boundary_checked,
    }
    path = _progress_path()
    temp_path = path + "." + uuid.uuid4().hex + ".tmp"
    try:
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, default=str)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, path)
    except (OSError, TypeError, ValueError) as exc:
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except OSError:
            pass
        st.warning(f"Progress could not be saved to local storage: {exc}. Export your work before closing this session.")


def load_progress():
    """Only load from disk once per browser session."""
    if st.session_state.get('_progress_loaded'):
        return
    try:
        path = _progress_path()
        if os.path.exists(path):
            with open(path) as f:
                p = json.load(f)
            st.session_state.completed_workshops = set(p.get("completed_workshops", []))
            st.session_state.unlocked_workshops = set(p.get("unlocked_workshops", ["1"])) | {"1"}
            sel = p.get("selected_workshop")
            st.session_state.selected_workshop = sel if sel in WORKSHOPS else None
            step = p.get("current_step", 1)
            st.session_state.current_step = step if isinstance(step, int) and 1 <= step <= 18 else 1
            st.session_state.threats = p.get("threats", [])
            st.session_state.user_answers = p.get("user_answers", [])
            st.session_state.total_score = p.get("total_score", 0)
            st.session_state.max_score = p.get("max_score", 0)
            st.session_state.annotations = p.get("annotations", {})
            st.session_state.scope_models = p.get("scope_models", {})
            st.session_state.open_questions = p.get("open_questions", {})
            st.session_state.review_plans = p.get("review_plans", {})
            st.session_state.stride_map = p.get("stride_map", {})
            st.session_state.boundary_checked = p.get("boundary_checked", {})
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        st.warning(f"Saved progress could not be loaded and was ignored: {exc}")
    st.session_state['_progress_loaded'] = True


load_progress()


def is_workshop_unlocked(ws_id):
    return ws_id in st.session_state.unlocked_workshops


# ─────────────────────────────────────────────────────────────────────────────
# PDF GENERATORS
# ─────────────────────────────────────────────────────────────────────────────
def generate_user_threat_model_pdf(workshop_config, user_answers, total_score, max_score, extra=None):
    try:
        (letter, getSampleStyleSheet, ParagraphStyle, inch, colors,
         SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table,
         TableStyle, TA_CENTER, TA_LEFT) = _get_reportlab()
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter,
                                topMargin=0.75 * inch, bottomMargin=0.75 * inch)
        styles = getSampleStyleSheet()
        story = []

        title_style = ParagraphStyle('T', parent=styles['Heading1'], fontSize=22,
                                     textColor=colors.HexColor('#3CAFA0'),
                                     spaceAfter=20, alignment=TA_CENTER)
        h2 = ParagraphStyle('H2', parent=styles['Heading2'], fontSize=14,
                            textColor=colors.HexColor('#217166'), spaceAfter=10, spaceBefore=10)

        story.append(Paragraph("STRIDE Threat Model Report", title_style))
        story.append(Paragraph(workshop_config['name'], styles['Heading2']))
        story.append(Spacer(1, 0.2 * inch))

        final_pct = (total_score / max_score * 100) if max_score else 0
        meta = [
            ['Report Type:', 'User Submission'],
            ['Workshop Level:', workshop_config['level']],
            ['Architecture:', workshop_config.get('architecture_type', 'N/A')],
            ['Methodology:', '10-Stage Threat Modeling'],
            ['Date:', datetime.now().strftime('%Y-%m-%d %H:%M')],
            ['Score:', f"{total_score}/{max_score} ({final_pct:.1f}%)"]
        ]
        t = Table(meta, colWidths=[2 * inch, 4 * inch])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#F1F0EF')),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(t)
        story.append(PageBreak())

        story.append(Paragraph("10-Stage Process Applied", h2))
        for s_ in ["Stage 1: Scope – system, requirements, assumptions, exclusions, goals",
                   "Stage 2: Architecture – components, environments, assets",
                   "Stage 3: DFD – elements (E, P, D) and data flows (F)",
                   "Stage 4: Trust boundaries – crossings and zones of trust",
                   "Stage 5: STRIDE – threat actors, per-element mapping, zone-direction rules",
                   "Stage 6: MITRE ATT&CK – techniques and tactics for each threat",
                   "Stage 7: Scoring – impact × likelihood on a 1–3 scale (risk 1–9)",
                   "Stage 8: Controls – guardrails, filtering, access rules, monitoring (OWASP-mapped)",
                   "Stage 9: Residual risk – risk after controls, decisions, open questions",
                   "Stage 10: Review – owner, cadence and update triggers"]:
            story.append(Paragraph(f"• {s_}", styles['Normal']))
        story.append(Spacer(1, 0.2 * inch))

        def _para(txt, bold=False):
            txt = _html.escape(str(txt))
            return Paragraph(f"<b>{txt}</b>" if bold else txt, styles['Normal'])

        def _grid(rows, widths, header=True):
            tb = Table([[_para(c, header and i == 0) for c in r] for i, r in enumerate(rows)], colWidths=[w * inch for w in widths], repeatRows=1 if header else 0)
            tb.setStyle(TableStyle([('GRID', (0, 0), (-1, -1), 0.5, colors.grey), ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                                    ('BACKGROUND', (0, 0), (-1, 0 if header else -1), colors.HexColor('#F1F0EF')) if header else ('LEFTPADDING', (0, 0), (-1, -1), 4),
                                    ('LEFTPADDING', (0, 0), (-1, -1), 4), ('TOPPADDING', (0, 0), (-1, -1), 3)]))
            return tb

        ex = extra or {}
        sc_ = ex.get("scope") or {}
        if sc_:
            story.append(Paragraph("Stage 1 – Scope", h2))
            story.append(_para("System in scope: " + (sc_.get("statement") or "—")))
            for title_, key_ in (("Must do", "must_do"), ("Must never", "must_never"), ("Measurable goals", "goals")):
                if sc_.get(key_):
                    story.append(Spacer(1, 0.05 * inch)); story.append(_para(title_, True))
                    for x_ in sc_[key_]:
                        story.append(_para("• " + x_))
            if sc_.get("assumptions"):
                story.append(Spacer(1, 0.08 * inch)); story.append(_para("Assumptions", True))
                story.append(_grid([["Assumption", "How we will verify", "Status"]] + [[a_.get("Assumption", ""), a_.get("How we will verify", ""), a_.get("Status", "")] for a_ in sc_["assumptions"]], [2.6, 2.6, 1.0]))
            if sc_.get("exclusions") or sc_.get("oos_components"):
                story.append(Spacer(1, 0.08 * inch)); story.append(_para("Exclusions (out of scope)", True))
                if sc_.get("exclusions"):
                    story.append(_grid([["Excluded item", "Reason"]] + [[e_.get("Excluded item", ""), e_.get("Reason", "")] for e_ in sc_["exclusions"]], [3.0, 3.2]))
                if sc_.get("oos_components"):
                    story.append(_para("Out-of-scope components: " + ", ".join(sc_["oos_components"])))
            story.append(Spacer(1, 0.2 * inch))

        story.append(Paragraph("Identified Threats", h2))
        for idx, answer in enumerate(user_answers, 1):
            pct = answer['score'] / answer['max_score'] * 100
            pred = answer.get('predefined_threat', {})
            story.append(Paragraph(f"Threat {idx}: {answer.get('matched_threat_id', 'N/A')}", styles['Heading3']))

            row = [
                ['Component:', answer['component']],
                ['STRIDE:', answer['stride']],
                ['Zone Rule:', pred.get('stride_rule_applied', 'N/A')],
                ['OWASP:', ', '.join(pred.get('owasp_categories', []))],
                ['Risk:', (f"{answer['likelihood']} × {answer['impact']} = {rec_risk(answer)}/9 ({risk_band(rec_risk(answer))})" if rec_risk(answer) else "Not rated")
                          + (f"  →  residual {rec_residual(answer)}/9 ({answer['residual']['decision']})" if rec_residual(answer) else "")],
                ['Score:', f"{answer['score']}/{answer['max_score']} ({pct:.0f}%)"]
            ]
            rt = Table(row, colWidths=[1.8 * inch, 4.5 * inch])
            rt.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#FBF5C8')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(rt)
            story.append(Spacer(1, 0.1 * inch))

            if answer.get('selected_mitigations'):
                story.append(Paragraph("<b>Selected Mitigations:</b>", styles['Normal']))
                for m in answer['selected_mitigations']:
                    story.append(Paragraph(f"• [{control_category(m)}] {_html.escape(m)}", styles['Normal']))
            story.append(Spacer(1, 0.2 * inch))

        ac_ = [l_ for l_ in (ex.get("labels") or []) if l_["kind"] == "actor"]
        if ac_:
            story.append(Paragraph("Stage 5 – Threat actors and entry points", h2))
            story.append(_grid([["ID", "Threat actor", "Capability", "Entry points"]] +
                               [[a_["id"], a_["label"], a_.get("capability", ""), ", ".join(_actor_targets(a_))] for a_ in sorted(ac_, key=_ann_sort)],
                               [0.6, 2.4, 0.9, 2.6]))
            story.append(Spacer(1, 0.15 * inch))
        sm_ = ex.get("stride_map") or {}
        if sm_:
            story.append(Paragraph("Stage 5 – STRIDE mapping per element", h2))
            story.append(_grid([["Element", "STRIDE categories"]] +
                               [[k_, ", ".join(STRIDE_NAMES.get(l_, l_) for l_ in v_)] for k_, v_ in sm_.items()], [2.8, 3.7]))
            story.append(Spacer(1, 0.15 * inch))
        mt_ = [a_ for a_ in user_answers if a_.get("mitre")]
        if mt_:
            story.append(Paragraph("Stage 6 – MITRE ATT&CK mapping (Enterprise v19)", h2))
            story.append(_grid([["Threat", "STRIDE", "ATT&CK techniques (tactics)"]] +
                               [[a_["matched_threat_id"], a_["stride"],
                                 "; ".join(f"{t_} {ATTACK_BY_ID[t_]['name']} ({', '.join(ATTACK_BY_ID[t_]['tactics'])})" for t_ in a_["mitre"] if t_ in ATTACK_BY_ID)]
                                for a_ in mt_], [0.8, 1.4, 4.3]))
            story.append(Spacer(1, 0.15 * inch))
        rated_ = [a_ for a_ in user_answers if rec_risk(a_)]
        if rated_:
            story.append(Paragraph("Stages 7–9 – Risk register (inherent → residual)", h2))
            story.append(_grid([["Threat", "Component / flow", "STRIDE", "Inherent", "Residual", "Decision"]] +
                               [[a_["matched_threat_id"], a_["component"], a_["stride"], str(rec_risk(a_)),
                                 str(rec_residual(a_) or "—"), (a_.get("residual") or {}).get("decision", "—")]
                                for a_ in sorted(rated_, key=lambda x: -rec_risk(x))], [0.7, 1.9, 1.3, 0.7, 0.7, 1.2]))
            story.append(Spacer(1, 0.15 * inch))
        oq_ = ex.get("open_questions") or {}
        if oq_.get("questions") or oq_.get("accepted"):
            story.append(Paragraph("Stage 9 – Open questions and accepted risk", h2))
            for q_ in oq_.get("questions", []):
                story.append(_para("• " + q_))
            if oq_.get("accepted"):
                story.append(Spacer(1, 0.05 * inch)); story.append(_para("Accepted-risk statement: " + oq_["accepted"]))
        rp_ = ex.get("review_plan") or {}
        if rp_.get("owner") or rp_.get("full"):
            story.append(Paragraph("Stage 10 – Review plan", h2))
            story.append(_para(f"Owner: {rp_.get('owner') or '—'}   |   Security role: {rp_.get('security_role') or '—'}   |   Next lightweight review: {rp_.get('next_review') or '—'}"))
            for title_, key_ in (("Full-workshop triggers", "full"), ("Lightweight review checks", "light"), ("Update triggers", "triggers")):
                if rp_.get(key_):
                    story.append(Spacer(1, 0.05 * inch)); story.append(_para(title_, True))
                    for x_ in rp_[key_]:
                        story.append(_para("• " + x_))
        labs_ = ex.get("labels") or []
        if labs_:
            story.append(Paragraph("Diagram labels (actors, assets, threat scenarios, controls)", h2))
            story.append(_grid([["ID", "Type", "Label", "Attached to"]] + [[l_["id"], ANNOTATION_KINDS[l_["kind"]]["title"], l_["label"], l_["target"]]
                                                                         for l_ in sorted(labs_, key=_ann_sort)], [0.6, 1.5, 2.7, 1.6]))

        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()
    except Exception as e:
        st.error(f"PDF error: {e}")
        return None


def generate_complete_threat_model_pdf(workshop_config, workshop_id):
    try:
        (letter, getSampleStyleSheet, ParagraphStyle, inch, colors,
         SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table,
         TableStyle, TA_CENTER, TA_LEFT) = _get_reportlab()
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter,
                                topMargin=0.75 * inch, bottomMargin=0.75 * inch)
        styles = getSampleStyleSheet()
        story = []

        all_threats = PREDEFINED_THREATS.get(workshop_id, [])

        title_style = ParagraphStyle('T', parent=styles['Heading1'], fontSize=22,
                                     textColor=colors.HexColor('#3CAFA0'),
                                     spaceAfter=20, alignment=TA_CENTER)
        h2 = ParagraphStyle('H2', parent=styles['Heading2'], fontSize=14,
                            textColor=colors.HexColor('#217166'), spaceAfter=10, spaceBefore=10)
        h3 = ParagraphStyle('H3', parent=styles['Heading3'], fontSize=12,
                            textColor=colors.HexColor('#305B31'), spaceAfter=8, spaceBefore=8)

        # Cover
        story.append(Paragraph("COMPREHENSIVE THREAT MODEL", title_style))
        story.append(Paragraph(workshop_config['name'], styles['Heading2']))
        story.append(Paragraph(workshop_config['scenario']['title'], styles['Heading3']))
        story.append(Spacer(1, 0.3 * inch))
        story.append(Paragraph("<b>Methodology:</b> 4-Step Infosec Threat Modeling (Design → Zones → STRIDE → OWASP Mitigations)", styles['Normal']))
        story.append(PageBreak())

        # Step 2: Zone Labels
        story.append(Paragraph("Step 2: Criticality Zone Labels", h2))
        zone_data = [['Component', 'Type', 'Zone', 'Score (0-9)', 'STRIDE Focus']]
        for comp in workshop_config['scenario']['components']:
            zone = comp.get('zone', 'Standard Application')
            zinfo = CRITICALITY_ZONES.get(zone, {})
            zone_data.append([
                comp['name'], comp['type'].replace('_', ' ').title(),
                zone, str(comp.get('zone_score', '?')),
                zinfo.get('stride_applicability', '')[:60]
            ])
        zt = Table(zone_data, colWidths=[1.2 * inch, 1.2 * inch, 1.5 * inch, 0.8 * inch, 2.5 * inch])
        zt.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#217166')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
        ]))
        story.append(zt)
        story.append(PageBreak())

        # Step 3: STRIDE Rules Applied
        story.append(Paragraph("Step 3: STRIDE Threat Discovery (Zone-Based Rules)", h2))
        stride_rule_text = """
        Threats are identified by applying STRIDE rules based on zone relationships:<br/>
        • <b>Tampering</b>: Data flow from LESS critical → MORE critical zone<br/>
        • <b>Information Disclosure</b>: Data flow from MORE critical → LESS critical zone<br/>
        • <b>Denial of Service</b>: Any flow from Zone 0 (Not in Control) → any other zone<br/>
        • <b>Spoofing</b>: Any node reachable by Zone 0 entities<br/>
        • <b>Repudiation</b>: Any node where both Spoofing AND Tampering apply<br/>
        • <b>Elevation of Privilege</b>: Any node connected to a lower-trust zone node
        """
        story.append(Paragraph(stride_rule_text, styles['Normal']))
        story.append(Spacer(1, 0.2 * inch))

        # Threat catalog
        story.append(Paragraph("Step 3 + 4: Full Threat Catalog with OWASP Controls", h2))
        for idx, threat in enumerate(all_threats, 1):
            story.append(Paragraph(f"{threat['id']}: {threat.get('threat', '')}", h3))
            row = [
                ['STRIDE:', threat['stride']],
                ['Component:', threat['component']],
                ['Zone Rule:', threat.get('stride_rule_applied', 'N/A')],
                ['Risk:', f"{threat['likelihood']} likelihood × {threat['impact']} impact"],
                ['OWASP:', ', '.join(threat.get('owasp_categories', []))],
                ['Compliance:', threat.get('compliance', 'N/A')]
            ]
            rt = Table(row, colWidths=[1.5 * inch, 5 * inch])
            rt.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#FBF5C8')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(rt)
            story.append(Spacer(1, 0.05 * inch))
            story.append(Paragraph(f"<b>Explanation:</b> {threat.get('explanation', '')}", styles['Normal']))
            story.append(Paragraph("<b>Mitigations (OWASP-aligned):</b>", styles['Normal']))
            for m in threat.get('correct_mitigations', []):
                story.append(Paragraph(f"• {m}", styles['Normal']))
            story.append(Paragraph(f"<b>Real-world example:</b> {threat.get('real_world', '')}", styles['Normal']))
            story.append(Spacer(1, 0.15 * inch))
            if idx % 2 == 0 and idx < len(all_threats):
                story.append(PageBreak())

        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()
    except Exception as e:
        st.error(f"Complete PDF error: {e}")
        import traceback; st.error(traceback.format_exc())
        return None


# ═══════════════════════════════════════════════════════════════════════════════
#  7-STAGE WORKFLOW:  Scope → DFD → STRIDE → Scoring → Controls → Residual risk → Review
#  Pages (current_step) 1-13 are grouped under these seven stages.
# ═══════════════════════════════════════════════════════════════════════════════
import html as _html
from datetime import date as _date, timedelta as _timedelta

def _esc(x):
    return _html.escape(str(x if x is not None else ""))


def go_page(page):
    st.session_state.current_step = page
    save_progress()
    st.rerun()


# ─────────────────────────────────────────────────────────────────────────────
# RISK SCALE (1-3 × 1-3 = 1-9) AND THE PER-THREAT RECORD
# ─────────────────────────────────────────────────────────────────────────────
LEVELS = ["Low", "Medium", "High"]
_LEVEL_N = {"Low": 1, "Medium": 2, "High": 3, "Critical": 3}
BAND_COLORS = {"Low": ("#EFEFEE", "#367539"), "Medium": ("#FAF0D2", "#CF8E17"), "High": ("#FAD2D6", "#B63838")}


def level_n(label):
    return _LEVEL_N.get(label, 0)


def risk_band(score):
    return "High" if score >= 6 else "Medium" if score >= 3 else "Low"


def rec_risk(rec):
    l, i = rec.get("likelihood_n"), rec.get("impact_n")
    return l * i if l and i else None


def rec_residual(rec):
    r = rec.get("residual")
    return r["likelihood_n"] * r["impact_n"] if r else None


def _score_identify(rec, pred):
    pts, fb = 0, []
    if rec["component"] == pred["component"]:
        pts += 2; fb.append("✓ Correct component identified")
    else:
        fb.append(f"✗ Wrong component. Expected: {pred['component']}")
    if rec["stride"] == pred["stride"]:
        pts += 2; fb.append("✓ Correct STRIDE category")
    else:
        fb.append(f"✗ Wrong STRIDE. Expected: {pred['stride']}")
    return pts, fb


def _score_rating(rec, pred):
    pts, fb = 0, []
    for fld in ("likelihood", "impact"):
        key_lbl = pred[fld]
        shown = "High" if key_lbl == "Critical" else key_lbl
        note = " (the key rates this Critical; Critical counts as High on the 1–3 scale)" if key_lbl == "Critical" else ""
        if level_n(rec.get(fld)) == level_n(key_lbl) and level_n(rec.get(fld)) > 0:
            pts += 1; fb.append(f"✓ Correct {fld}")
        else:
            fb.append(f"✗ {fld.capitalize()} should be: {shown}{note}")
    return pts, fb


def _score_controls(rec, pred):
    pts, fb = 0, []
    correct, incorrect = set(pred["correct_mitigations"]), set(pred.get("incorrect_mitigations", []))
    chosen = set(rec.get("selected_mitigations", []))
    ok, bad = chosen & correct, chosen & incorrect
    if len(ok) >= 3:
        pts += 4; fb.append(f"✓ Excellent control selection ({len(ok)} correct)")
    elif len(ok) == 2:
        pts += 3; fb.append(f"✓ Good control selection ({len(ok)} correct)")
    elif len(ok) == 1:
        pts += 2; fb.append(f"⚠ Partial control selection ({len(ok)} correct)")
    else:
        fb.append("✗ No correct controls selected")
    if bad:
        pts -= len(bad)
        fb.append(f"✗ Incorrect controls penalty: {', '.join(sorted(bad))}")
    return pts, fb


def rescore_record(rec):
    """Score a threat record from the stages completed so far (identify 4 pts, rating 2, controls 4)."""
    pred = rec["predefined_threat"]
    pts, mx = 0, 0
    p, rec["fb_identify"] = _score_identify(rec, pred); rec["pts_identify"] = p; pts += p; mx += 4
    fb = list(rec["fb_identify"])
    if rec.get("rated"):
        p, rec["fb_rating"] = _score_rating(rec, pred); pts += p; mx += 2; fb += rec["fb_rating"]
    if rec.get("controlled"):
        p, rec["fb_controls"] = _score_controls(rec, pred); pts += p; mx += 4; fb += rec["fb_controls"]
    rec["score"], rec["max_score"], rec["feedback"] = max(0, pts), mx, fb


def calculate_threat_score(user_threat, predefined_threat):
    """Compatibility helper: full score for a complete answer."""
    rec = {**user_threat, "predefined_threat": predefined_threat, "rated": True, "controlled": True}
    rescore_record(rec)
    return rec["score"], rec["max_score"], rec["feedback"]


def recalc_totals():
    ans = st.session_state.user_answers
    st.session_state.total_score = sum(a["score"] for a in ans)
    st.session_state.max_score = sum(a["max_score"] for a in ans)
    st.session_state.threats = [
        {k: a.get(k) for k in ("component", "stride", "likelihood", "impact", "selected_mitigations", "matched_threat_id")}
        for a in ans]


def new_record(component, stride, pred):
    rec = {"component": component, "stride": stride, "matched_threat_id": pred["id"],
           "threat_statement": "", "threat_source": "", "prerequisites": "", "threat_action": "",
           "threat_impact": "", "impacted_assets": "", "statement_rationale": "",
           "capec": [], "capec_rationale": "", "likelihood_rationale": "", "impact_rationale": "",
           "likelihood": "Not rated", "impact": "Not rated", "likelihood_n": None, "impact_n": None,
           "rated": False, "selected_mitigations": [], "controlled": False, "residual": None,
           "predefined_threat": pred, "score": 0, "max_score": 4, "feedback": []}
    rescore_record(rec)
    return rec


# Curated CAPEC prompts for teaching. Candidate patterns only: validate the IDs/titles
# against the current MITRE CAPEC catalogue before using this as authoritative reference data.
CAPEC_CANDIDATES = {
    "CAPEC-1 — Accessing Functionality Not Properly Constrained by ACLs": "Missing or incorrect authorisation checks.",
    "CAPEC-21 — Exploitation of Trusted Identifiers": "An attacker-controlled or predictable identifier exposes another object.",
    "CAPEC-62 — Cross Site Request Forgery (CSRF)": "A victim's authenticated browser is induced to perform an unintended action.",
    "CAPEC-66 — SQL Injection": "Untrusted input alters a database query's structure.",
    "CAPEC-18 — XSS Targeting Non-Script Elements": "Attacker-controlled content is interpreted as executable or active content in a victim context; confirm the specific XSS variant fits.",
    "CAPEC-588 — DOM-Based XSS": "Client-side code uses attacker-controlled input in an unsafe DOM sink.",
    "CAPEC-591 — Reflected XSS": "Attacker-controlled input is reflected into a response and executed in a victim context.",
    "CAPEC-592 — Stored XSS": "Attacker-controlled content is stored and later executed in another user's context.",
    "CAPEC-115 — Authentication Bypass": "An authentication mechanism can be bypassed.",
    "CAPEC-153 — Input Data Manipulation": "Input changes alter business logic or processing.",
    "CAPEC-560 — Use of Known Domain Credentials": "The scenario involves valid credentials obtained or reused by an attacker.",
    "No suitable CAPEC pattern identified": "Valid when the scenario does not support a confident CAPEC mapping."
}

# ─────────────────────────────────────────────────────────────────────────────
# CONTROL CATEGORIES (guardrails · filtering · access rules · monitoring)
# ─────────────────────────────────────────────────────────────────────────────
CONTROL_CATEGORIES = {
    "Guardrails":   ("🧱", "Secure-by-design defaults and architecture constraints: encryption, safe configuration, failure containment."),
    "Filtering":    ("🧪", "Checks on what goes in and out: validation, sanitisation, parameterised queries, output encoding, error hygiene."),
    "Access rules": ("🔑", "Limits on who/what can do what: authentication, authorisation, least privilege, rate limits, segmentation."),
    "Monitoring":   ("📡", "Detects what prevention misses: logging, audit trails, alerting, anomaly detection."),
}
_CAT_PATTERNS = [
    ("Monitoring", r"\b(?:log(?!in|ic)|audit|monitor|alert|siem|anomal|trac(?:e|ing)|detect|cloudtrail|forensic|telemetry|timestamp|nonce)"),
    ("Filtering",  r"\b(?:validat|sanitiz|sanitis|parameteri|prepared|orm\b|encod|escap|csp\b|content security|waf\b|filter|schema|allowlist|whitelist|blacklist|strip\b|dlp\b|mask|redact|generic error|avoid dangerously)"),
    ("Access rules", r"\b(?:auth|mfa|token|rbac|abac|least privilege|permission|role|tenant|limit|quota|throttl|mtls|mutual tls|spiffe|segment|isolation|vlan|firewall|security group|iam\b|ownership|deny|session|jwt|oauth|hmac|signature|certificate|pinning|access)"),
]


def control_category(text):
    t = str(text).lower()
    for cat, pat in _CAT_PATTERNS:
        if re.search(pat, t):
            return cat
    return "Guardrails"


def control_coverage(controls):
    cats = {}
    for c in controls:
        cats.setdefault(control_category(c), []).append(c)
    return cats


def _control_chips(controls):
    cats = control_coverage(controls)
    chips = []
    for cat, (ic, _) in CONTROL_CATEGORIES.items():
        n = len(cats.get(cat, []))
        bg, fg = ("#EFEFEE", "#205924") if n else ("#F6F5F4", "#A6A196")
        chips.append(f'<span style="background:{bg};color:{fg};padding:2px 10px;border-radius:12px;font-size:0.8em;'
                     f'margin-right:6px;border:1px solid {fg}33">{ic} {cat}: {n}</span>')
    return "".join(chips)


def risk_matrix_html(items, title="Likelihood →"):
    """items: list of (likelihood_n, impact_n, label)."""
    cells = {}
    for l, i, lab in items:
        if l and i:
            cells.setdefault((l, i), []).append(lab)
    rows = []
    for i in (3, 2, 1):
        tds = [f'<td style="padding:6px 10px;font-weight:700;font-size:0.8em;color:#5B574E;text-align:right;white-space:nowrap">{LEVELS[i-1]} impact</td>']
        for l in (1, 2, 3):
            fill, stroke = BAND_COLORS[risk_band(l * i)]
            labs = ", ".join(_esc(x) for x in cells.get((l, i), []))
            tds.append(f'<td style="background:{fill};border:2px solid {stroke};padding:8px;min-width:110px;height:62px;'
                       f'text-align:center;vertical-align:middle"><div style="font-size:0.7em;color:{stroke};font-weight:700">{l*i}</div>'
                       f'<div style="font-size:0.82em;font-weight:700;color:#222">{labs}</div></td>')
        rows.append("<tr>" + "".join(tds) + "</tr>")
    head = ('<tr><td></td>' + "".join(f'<td style="text-align:center;font-weight:700;font-size:0.8em;color:#5B574E;padding:4px">{LEVELS[l-1]}</td>'
                                       for l in (1, 2, 3)) + "</tr>")
    foot = f'<tr><td></td><td colspan="3" style="text-align:center;font-size:0.75em;color:#948D80;padding-top:4px">{title}</td></tr>'
    return f'<table style="border-collapse:separate;border-spacing:4px;margin:6px 0">{head}{"".join(rows)}{foot}</table>'


# ─────────────────────────────────────────────────────────────────────────────
# SCOPE / OPEN QUESTIONS / REVIEW-PLAN MODELS (per workshop)
# ─────────────────────────────────────────────────────────────────────────────
def get_scope(ws_id=None):
    ws_id = ws_id or st.session_state.selected_workshop
    sc = st.session_state.scope_models.setdefault(ws_id, {})
    for k, v in (("statement", ""), ("must_do", []), ("must_never", []), ("assumptions", []),
                 ("exclusions", []), ("oos_components", []), ("goals", [])):
        sc.setdefault(k, v)
    return sc


def get_open_questions(ws_id=None):
    ws_id = ws_id or st.session_state.selected_workshop
    d = st.session_state.open_questions.setdefault(ws_id, {})
    d.setdefault("questions", []); d.setdefault("accepted", "")
    return d


def get_review_plan(ws_id=None):
    ws_id = ws_id or st.session_state.selected_workshop
    d = st.session_state.review_plans.setdefault(ws_id, {})
    for k, v in (("owner", ""), ("security_role", "Security — expertise and challenge"), ("next_review", ""),
                 ("full", []), ("light", []), ("triggers", []), ("notes", "")):
        d.setdefault(k, v)
    return d


def scope_checks(sc):
    """(ok, text, required) — required items gate the Next button."""
    goal_ok = any(any(ch.isdigit() for ch in g) for g in sc["goals"])
    return [
        (len(sc["statement"].strip()) >= 25, "A specific scope statement (one deployed system, not “our platform”)", True),
        (len(sc["must_do"]) >= 1, "At least one thing the system MUST do", True),
        (len(sc["must_never"]) >= 1, "At least one thing the system must NEVER do (becomes a security requirement)", True),
        (len(sc["assumptions"]) >= 1, "At least one explicit assumption", True),
        (len(sc["exclusions"]) + len(sc["oos_components"]) >= 1, "At least one exclusion (what is out of scope)", True),
        (goal_ok, "A measurable success goal (contains a number or threshold)", False),
    ]


def scope_complete(sc):
    return all(ok for ok, _, req in scope_checks(sc) if req)


def scope_reminder():
    sc = get_scope()
    if sc["statement"].strip():
        st.caption(f"📐 **In scope:** {sc['statement'].strip()[:160]}  ·  {len(sc['assumptions'])} assumptions  ·  "
                   f"{len(sc['exclusions']) + len(sc['oos_components'])} exclusions")
    else:
        st.caption("📐 Scope not defined yet — Step 1 documents what is in scope, excluded and assumed.")


def scope_examples(cfg):
    s = cfg["scenario"]
    comps = s["components"]
    third = [c["name"] for c in comps if c["type"] == "external_entity" and _is_third_party(cfg, c)]
    users = [c["name"] for c in comps if c["type"] == "external_entity" and not _is_third_party(cfg, c)]
    assets = s.get("assets", []) or ["sensitive data"]
    return {
        "statement": f"{s['title']} — {s['description']} ({cfg.get('architecture_type', 'architecture')})"
                     + (f", integrated with {', '.join(third)}" if third else "") + ".",
        "must_do": [f"Preserve: {o}" for o in s.get("objectives", [])[:3]],
        "must_never": [f"Never disclose {a} to unauthorised parties" for a in assets[:2]]
                      + ["Never accept state-changing requests from unauthenticated callers"],
        "assumptions": [
            {"Assumption": "All callers are authenticated before reaching internal services",
             "How we will verify": "Review gateway/auth configuration; test an unauthenticated request", "Status": "Unverified"},
            {"Assumption": f"{third[0]} is trustworthy and its integration is secured" if third else "Cloud provider controls are configured as documented",
             "How we will verify": "Vendor security report / contract review", "Status": "Unverified"},
        ],
        "exclusions": [
            {"Excluded item": "Physical security of data centres / provider facilities", "Reason": "Covered by the provider's shared-responsibility model"},
            {"Excluded item": "Security of end-user devices", "Reason": "Outside our control"},
        ],
        "goals": ["No high-severity security incident in production this quarter",
                  "Mean time to detect an attack under 4 hours",
                  "100% of Zone 7+ data stores have encryption and audit logging"],
    }


def _apply_scope_examples(ws_id):
    ex = scope_examples(WORKSHOPS[ws_id])
    sc = get_scope(ws_id)
    for fld, key in (("statement", f"w_stmt_{ws_id}"), ("must_do", f"w_must_do_{ws_id}"),
                     ("must_never", f"w_must_never_{ws_id}"), ("goals", f"w_goals_{ws_id}")):
        if not sc[fld]:
            sc[fld] = ex[fld]
            st.session_state[key] = ex[fld] if fld == "statement" else "\n".join(ex[fld])
    for kind, fld in (("assump", "assumptions"), ("excl", "exclusions")):
        if not sc[fld]:
            sc[fld] = ex[fld]
            st.session_state[f"_seed_{kind}_{ws_id}"] = pd.DataFrame(ex[fld])
            st.session_state.pop(f"w_ed_{kind}_{ws_id}", None)


def _lines(text):
    return [ln.strip(" -•\t") for ln in str(text).splitlines() if ln.strip(" -•\t")]


def _table_editor(ws_id, kind, cols, rows, column_config=None):
    sk = f"_seed_{kind}_{ws_id}"
    if sk not in st.session_state:
        st.session_state[sk] = pd.DataFrame(rows, columns=cols)
    df = st.data_editor(st.session_state[sk], num_rows="dynamic", key=f"w_ed_{kind}_{ws_id}",
                        use_container_width=True, hide_index=True, column_config=column_config or {})
    out = []
    for r in df.fillna("").to_dict("records"):
        row = {c: str(r.get(c, "")).strip() for c in cols}
        if row[cols[0]]:
            out.append(row)
    return out


# ═══════════════════════════════════════════════════════════════════════════════
#  PAGE 1 — SCOPE
# ═══════════════════════════════════════════════════════════════════════════════
def render_scope_page():
    ws = st.session_state.selected_workshop
    cfg = WORKSHOPS[ws]
    s = cfg["scenario"]
    sc = get_scope(ws)
    names = [c["name"] for c in s["components"]]

    st.header("Step 1: Define Scope & Goals")
    st.markdown("""
    <div class="methodology-step">
    <strong>📐 Stage 1 · Scope</strong><br>
    Draw a box around what you are protecting. A threat model cannot boil the ocean — pick <strong>one deployed system</strong>.
    Write down what it <strong>must do</strong> and <strong>must never do</strong> (these become your security requirements),
    document your <strong>assumptions</strong> and <strong>exclusions</strong> explicitly, and set <strong>measurable goals</strong>.
    <em>Half of security incidents come from violated assumptions nobody thought to verify.</em><br>
    ⏱️ Time-box: perfect clarity matters less than starting. Spend about 10 minutes here.
    </div>""", unsafe_allow_html=True)

    c1, c2 = st.columns([3, 2])
    with c1:
        st.markdown(f"**System:** {s['title']} — {s['description']}")
        st.markdown(f"**Business context:** {s['business_context']}")
        st.markdown("**Security objectives:** " + " · ".join(s["objectives"]))
    with c2:
        st.markdown("**Assets in play:** " + ", ".join(s.get("assets", [])))
        st.markdown("**Compliance drivers:** " + ", ".join(s.get("compliance", [])))

    st.button("💡 Fill empty fields with scenario-based examples", key="w_scope_examples",
              on_click=_apply_scope_examples, args=(ws,),
              help="Only fills fields that are still empty. Edit the examples so they reflect your own reasoning.")

    st.markdown("### 1️⃣ What exactly are you protecting?")
    st.caption("Bad: “Our platform”.  Good: one named system, its version/platform, key services and integrations.")
    statement = st.text_area("System in scope", value=sc["statement"], key=f"w_stmt_{ws}", height=90, max_chars=500,
                             placeholder=f"e.g. {s['title']} v2.0 — {s['description']}, integrated with ...")

    st.markdown("### 2️⃣ Security requirements")
    cc1, cc2 = st.columns(2)
    with cc1:
        must_do = st.text_area("The system MUST … (one per line)", value="\n".join(sc["must_do"]),
                               key=f"w_must_do_{ws}", height=130)
    with cc2:
        must_never = st.text_area("The system must NEVER … (one per line)", value="\n".join(sc["must_never"]),
                                  key=f"w_must_never_{ws}", height=130)

    st.markdown("### 3️⃣ Assumptions")
    st.caption("State what you are taking for granted, and how you would verify it. Unverified assumptions are risks.")
    assumptions = _table_editor(
        ws, "assump", ["Assumption", "How we will verify", "Status"], sc["assumptions"],
        {"Status": st.column_config.SelectboxColumn("Status", options=["Unverified", "Verified", "Disproved"], default="Unverified")})

    st.markdown("### 4️⃣ Exclusions (out of scope)")
    st.caption("Say what you are deliberately NOT analysing and why. Components marked out of scope are greyed on every diagram.")
    exclusions = _table_editor(ws, "excl", ["Excluded item", "Reason"], sc["exclusions"])
    oos = st.multiselect("Components that are OUT of scope", names,
                         default=[n for n in sc["oos_components"] if n in names], key=f"w_oos_{ws}")

    st.markdown("### 5️⃣ Measurable goals")
    goals = st.text_area("What does success look like? (one per line, with numbers)", value="\n".join(sc["goals"]),
                         key=f"w_goals_{ws}", height=90,
                         placeholder="e.g. Mean time to detect an attack under 4 hours")

    new = {"statement": statement.strip(), "must_do": _lines(must_do), "must_never": _lines(must_never),
           "assumptions": assumptions, "exclusions": exclusions, "oos_components": list(oos), "goals": _lines(goals)}
    if any(sc[k] != v for k, v in new.items()):
        sc.update(new)
        save_progress()

    st.markdown("---")
    st.subheader("🗺️ Scope view")
    show_architecture_diagram(cfg, mode="scope", key_suffix="s1_scope", editable=True, default_kind="asset")

    st.subheader("✅ Scope checklist")
    for ok, text, req in scope_checks(sc):
        st.markdown(f"{'✅' if ok else ('⚠️' if req else '➖')} {text}" + ("" if req else " *(recommended)*"))

    nav_buttons(None, "", 2, "Next: Draw the DFD ➡️", scope_complete(sc),
                "Complete the required scope items above before moving on.", key="p1")


# ═══════════════════════════════════════════════════════════════════════════════
#  PAGE 6 helper — record the learner's identified threats
# ═══════════════════════════════════════════════════════════════════════════════
# ═══════════════════════════════════════════════════════════════════════════════
#  PAGE 7 — SCORING (impact × likelihood, 1-3 scale)
# ═══════════════════════════════════════════════════════════════════════════════
def render_scoring_page():
    cfg = current_workshop
    recs = st.session_state.user_answers
    st.header("Step 7: Score the Risk — Impact × Likelihood")
    scope_reminder()
    st.markdown("""
    <div class="methodology-step">
    <strong>📊 Stage 7 · Scoring</strong><br>
    Not all threats deserve equal attention. Score each one for <strong>impact</strong> and <strong>likelihood</strong> on a simple
    <strong>1–3 scale</strong> (Low / Medium / High) and multiply them for a <strong>risk score from 1 to 9</strong>.
    Do not spend hours debating whether something is a 2 or a 3 — the goal is rough prioritisation, not precision.
    </div>""", unsafe_allow_html=True)
    with st.expander("📏 How to judge impact and likelihood", expanded=False):
        g1, g2 = st.columns(2)
        g1.markdown("""**Impact** — technical *and* business consequences
- **High (3):** data breach affecting many customers, complete outage, regulatory violation
- **Medium (2):** individual privacy violation, degraded service, reputational damage
- **Low (1):** minor functionality issue, more support tickets""")
        g2.markdown("""**Likelihood** — attacker motivation and capability
- **High (3):** needs only public access, financially motivated, tools exist
- **Medium (2):** needs authenticated access or moderate skill
- **Low (1):** needs physical access or nation-state capability""")

    if not recs:
        st.warning("Identify at least one threat first.")
        nav_buttons(6, "⬅️ Back to Identify Threats", None, "", key="p7e")
        return

    with st.form("scoring_form"):
        st.subheader("➕ Rate each threat")
        vals = {}
        for rec in recs:
            pred = rec["predefined_threat"]
            st.markdown(f"**{pred['id']} · {rec['stride']} on {rec['component']}**")
            st.caption(pred["threat"])
            a, b = st.columns(2)
            lik = a.select_slider("Likelihood", options=LEVELS, key=f"w_lik_{pred['id']}",
                                  value=rec["likelihood"] if rec["likelihood"] in LEVELS else "Low")
            imp = b.select_slider("Impact", options=LEVELS, key=f"w_imp_{pred['id']}",
                                  value=rec["impact"] if rec["impact"] in LEVELS else "Low")
            why_lik = st.text_input("Likelihood rationale / evidence", value=rec.get("likelihood_rationale", ""),
                                    key=f"w_likwhy_{pred['id']}", max_chars=300,
                                    placeholder="e.g. internet reachable; exploit prerequisites are low")
            why_imp = st.text_input("Impact rationale / evidence", value=rec.get("impact_rationale", ""),
                                    key=f"w_impwhy_{pred['id']}", max_chars=300,
                                    placeholder="e.g. customer records exposed; regulatory impact")
            vals[pred["id"]] = (lik, imp, why_lik, why_imp)
            st.markdown("---")
        if st.form_submit_button("📊 Score all threats", type="primary", use_container_width=True):
            for rec in recs:
                lik, imp, why_lik, why_imp = vals[rec["matched_threat_id"]]
                rec.update(likelihood=lik, impact=imp, likelihood_n=level_n(lik), impact_n=level_n(imp), rated=True,
                           likelihood_rationale=(why_lik or "").strip(), impact_rationale=(why_imp or "").strip())
                rescore_record(rec)
            recalc_totals()
            save_progress()
            st.rerun()

    rated = [r for r in recs if r.get("rated")]
    if rated:
        st.subheader("🎯 Risk register (highest first)")
        ordered = sorted(rated, key=lambda r: -rec_risk(r))
        st.dataframe(pd.DataFrame([{
            "Threat": r["matched_threat_id"], "Component / flow": r["component"], "STRIDE": r["stride"],
            "Likelihood": f"{r['likelihood']} ({r['likelihood_n']})", "Impact": f"{r['impact']} ({r['impact_n']})",
            "Risk (1–9)": rec_risk(r), "Band": risk_band(rec_risk(r)),
            "Priority": "Controls required" if rec_risk(r) >= 6 else "Plan controls" if rec_risk(r) >= 3 else "Accept / monitor"}
            for r in ordered]), use_container_width=True, hide_index=True)
        m1, m2 = st.columns([1, 1])
        with m1:
            st.markdown("**Risk matrix**")
            st.markdown(risk_matrix_html([(r["likelihood_n"], r["impact_n"], r["matched_threat_id"]) for r in rated]),
                        unsafe_allow_html=True)
        with m2:
            st.markdown("**How your ratings compare**")
            for r in ordered:
                fb = r.get("fb_rating", [])
                with st.expander(f"{r['matched_threat_id']} — risk {rec_risk(r)} ({risk_band(rec_risk(r))})"):
                    for line in fb:
                        (st.success if line.startswith("✓") else st.error)(line)
                    why = r["predefined_threat"].get("why_this_risk")
                    if why:
                        st.markdown(f"""<div style="background:#FDF7E3;border-left:4px solid #E9A435;border-radius:6px;padding:10px 14px">
                        <strong style="color:#D55611;font-size:0.85em">⚖️ WHY THIS RISK LEVEL</strong><br>
                        <span style="font-size:0.88em;color:#444">{why}</span></div>""", unsafe_allow_html=True)
        tabs = st.tabs(["🔥 Risk heat map", "🏗️ Clean architecture"])
        with tabs[0]:
            show_architecture_diagram(cfg, mode="scoring", key_suffix="s7_heat")
        with tabs[1]:
            show_architecture_diagram(cfg, mode="architecture", key_suffix="s7_arch")

    nav_buttons(6, "⬅️ Back to Identify Threats", 8, "Next: Map STRIDE to controls ➡️",
                bool(recs) and all(r.get("rated") for r in recs), "Rate every threat (press “Score all threats”) first.", key="p7")


# ═══════════════════════════════════════════════════════════════════════════════
#  PAGE 9 — SELECT CONTROLS
# ═══════════════════════════════════════════════════════════════════════════════
def render_controls_page():
    cfg = current_workshop
    recs = st.session_state.user_answers
    st.header("Step 8: Pick Controls for the Risks that Matter")
    scope_reminder()
    st.markdown("""
    <div class="methodology-step">
    <strong>🛡️ Stage 8 · Controls</strong><br>
    For each high-risk threat choose practical controls, and be able to say <em>why</em> each one is there and which threat it addresses.
    Controls fall into four categories — aim for <strong>defence in depth</strong>: at least one preventive control
    (guardrails, filtering or access rules) <em>and</em> monitoring to detect what prevention misses.
    </div>""", unsafe_allow_html=True)
    cols = st.columns(4)
    for col, (cat, (ic, desc)) in zip(cols, CONTROL_CATEGORIES.items()):
        col.markdown(f"**{ic} {cat}**")
        col.caption(desc)

    rated = [r for r in recs if r.get("rated")]
    if not rated:
        st.warning("Score your threats first (Step 4).")
        nav_buttons(8, "⬅️ Back to OWASP mapping", None, "", key="p9e")
        return
    ordered = sorted(rated, key=lambda r: -rec_risk(r))

    with st.form("controls_form"):
        st.subheader("➕ Select controls (highest risk first)")
        chosen = {}
        for rec in ordered:
            pred = rec["predefined_threat"]
            band = risk_band(rec_risk(rec))
            fill, stroke = BAND_COLORS[band]
            st.markdown(f"""<div style="background:{fill};border-left:5px solid {stroke};border-radius:8px;padding:8px 14px;margin-top:6px">
            <strong>{pred['id']} · {rec['stride']} on {_esc(rec['component'])}</strong> — risk <strong>{rec_risk(rec)}</strong> ({band})<br>
            <span style="font-size:0.88em;color:#444">{pred['threat']}</span></div>""", unsafe_allow_html=True)
            owasp = OWASP_STRIDE_MAP.get(pred["stride"], {})
            if owasp:
                st.caption(f"OWASP: {', '.join(owasp['owasp'])} — {owasp.get('owasp_detail', '')}")
            correct, wrong = pred["correct_mitigations"], pred.get("incorrect_mitigations", [])
            options = correct + wrong
            seed = int(hashlib.md5(pred["id"].encode()).hexdigest(), 16) % 10000
            random.Random(seed).shuffle(options)
            st.markdown(f"*{len(correct)} correct controls, {len(wrong)} distractors — choose wisely*")
            chosen[pred["id"]] = st.multiselect(
                "Controls (select all that apply)", options, key=f"w_ctl_{pred['id']}",
                default=[m for m in rec.get("selected_mitigations", []) if m in options])
            st.markdown("---")
        if st.form_submit_button("🛡️ Submit controls", type="primary", use_container_width=True):
            for rec in ordered:
                rec["selected_mitigations"] = list(chosen[rec["matched_threat_id"]])
                rec["controlled"] = True
                rescore_record(rec)
            recalc_totals()
            save_progress()
            st.rerun()

    done = [r for r in ordered if r.get("controlled")]
    if done:
        st.subheader("🧭 Defence-in-depth check")
        for rec in done:
            pred = rec["predefined_threat"]
            cats = control_coverage(rec["selected_mitigations"])
            prevent = any(c in cats for c in ("Guardrails", "Filtering", "Access rules"))
            detect = "Monitoring" in cats
            band = risk_band(rec_risk(rec))
            if band == "High" and (not prevent or not detect):
                miss = "a preventive control" if not prevent else "monitoring to detect failures"
                badge = f"⚠️ High-risk threat is missing {miss}"
            elif not rec["selected_mitigations"]:
                badge = "⚠️ No controls selected"
            else:
                badge = "✅ Layered coverage" if prevent and detect else "ℹ️ Preventive only — consider monitoring" if prevent else "ℹ️ Detective only — consider a preventive control"
            with st.expander(f"{pred['id']} — {badge}"):
                st.markdown(_control_chips(rec["selected_mitigations"]), unsafe_allow_html=True)
                _hints = attack_mitigation_hints(rec)
                if _hints:
                    st.caption("🎯 ATT&CK mitigations for the techniques you mapped: " +
                               "; ".join((f"{k} {v}" if k.startswith("M") else f"{k}: {v}") for k, v in _hints.items()))
                for line in rec.get("fb_controls", []):
                    (st.success if line.startswith("✓") else st.error if line.startswith("✗") else st.warning)(line)
                for m in rec["selected_mitigations"]:
                    st.markdown(f"- {CONTROL_CATEGORIES[control_category(m)][0]} **{control_category(m)}** — {m}")
                why = pred.get("why_these_controls")
                if why:
                    st.markdown(f"""<div style="background:#EFEFEE;border-left:4px solid #4A994D;border-radius:6px;padding:10px 14px">
                    <strong style="color:#205924;font-size:0.85em">🛡️ WHY THESE CONTROLS</strong><br>
                    <span style="font-size:0.88em;color:#444">{why}</span></div>""", unsafe_allow_html=True)

        st.subheader("🗺️ Controls on the architecture")
        if st.button("🏷️ Add my threats and controls to the diagram labels", key="w_sync_labels"):
            n = sync_labels_from_analysis(include_controls=True)
            save_progress()
            st.success(f"Added {n} label(s).") if n else st.info("Labels are already up to date.")
            st.rerun()
        show_architecture_diagram(cfg, mode="controls", key_suffix="s9_ctl", editable=True, default_kind="control")

    nav_buttons(8, "⬅️ Back to OWASP mapping", 10, "Next: Residual risk ➡️",
                bool(rated) and all(r.get("controlled") for r in rated), "Submit controls for every threat first.", key="p9")


# ═══════════════════════════════════════════════════════════════════════════════
#  PAGE 10 — RESIDUAL RISK
# ═══════════════════════════════════════════════════════════════════════════════
DECISIONS = ["Accept", "Reduce further", "Transfer (insurance / vendor)", "Avoid (remove the feature)"]
_CONTAINMENT = ["encrypt", "segment", "isolation", "backup", "quota", "least privilege", "row-level", "rls", "redact", "mask"]


def suggested_residual(rec):
    pred = rec["predefined_threat"]
    good = [m for m in rec.get("selected_mitigations", []) if m in set(pred["correct_mitigations"])]
    cats = {control_category(m) for m in good}
    lik, imp = rec["likelihood_n"], rec["impact_n"]
    if cats & {"Guardrails", "Filtering", "Access rules"}:
        lik = max(1, lik - (2 if len(good) >= 3 else 1))
    if any(any(k in m.lower() for k in _CONTAINMENT) for m in good):
        imp = max(1, imp - 1)
    return lik, imp


def render_residual_page():
    cfg = current_workshop
    recs = [r for r in st.session_state.user_answers if r.get("controlled")]
    oq = get_open_questions()
    st.header("Step 9: Residual Risk & Open Questions")
    scope_reminder()
    st.markdown("""
    <div class="methodology-step">
    <strong>⚖️ Stage 9 · Residual risk</strong><br>
    Controls reduce risk; they rarely remove it. For every threat, re-score <strong>what remains after your controls</strong>,
    decide what to do about it, and write down what you do <strong>not</strong> know. Documenting residual risk sets realistic
    expectations, guides incident response and gives future team members context.
    </div>""", unsafe_allow_html=True)
    if not recs:
        st.warning("Select controls first (Step 5).")
        nav_buttons(9, "⬅️ Back to Controls", None, "", key="p10e")
        return

    st.caption("Controls usually lower **likelihood**. Impact only drops with containment (segmentation, encryption, quotas, backups). "
               "The suggestion below is based on the *correct* controls you selected.")
    errors = []
    with st.form("residual_form"):
        vals = {}
        for rec in sorted(recs, key=lambda r: -rec_risk(r)):
            pred = rec["predefined_threat"]
            sl, si = suggested_residual(rec)
            cur = rec.get("residual") or {}
            st.markdown(f"**{pred['id']} · {rec['stride']} on {rec['component']}** — inherent risk **{rec_risk(rec)}** "
                        f"({rec['likelihood']} × {rec['impact']})")
            st.caption(f"Suggested residual: likelihood {LEVELS[sl-1]}, impact {LEVELS[si-1]} → {sl*si}")
            a, b, c = st.columns([1, 1, 1])
            rl = a.select_slider("Residual likelihood", LEVELS, key=f"w_rl_{pred['id']}", value=LEVELS[cur.get("likelihood_n", sl) - 1])
            ri = b.select_slider("Residual impact", LEVELS, key=f"w_ri_{pred['id']}", value=LEVELS[cur.get("impact_n", si) - 1])
            dec = c.selectbox("Decision", DECISIONS, key=f"w_dec_{pred['id']}",
                              index=DECISIONS.index(cur["decision"]) if cur.get("decision") in DECISIONS else 0)
            why = st.text_input("Rationale (why is this acceptable / what else is needed?)", value=cur.get("rationale", ""),
                                key=f"w_why_{pred['id']}", max_chars=200)
            vals[pred["id"]] = (rl, ri, dec, why)
            st.markdown("---")
        if st.form_submit_button("⚖️ Save residual risk", type="primary", use_container_width=True):
            for rec in recs:
                rl, ri, dec, why = vals[rec["matched_threat_id"]]
                rl_n, ri_n = level_n(rl), level_n(ri)
                pid = rec["matched_threat_id"]
                if rl_n > rec["likelihood_n"] or ri_n > rec["impact_n"]:
                    errors.append(f"{pid}: residual risk cannot be higher than inherent risk — your controls should not make things worse.")
                if rl_n * ri_n >= 6 and dec == DECISIONS[0] and len(why.strip()) < 10:
                    errors.append(f"{pid}: accepting a HIGH residual risk (≥ 6) needs a written rationale and a named owner.")
            if not errors:
                for rec in recs:
                    rl, ri, dec, why = vals[rec["matched_threat_id"]]
                    rec["residual"] = {"likelihood_n": level_n(rl), "impact_n": level_n(ri), "decision": dec, "rationale": why.strip()}
                save_progress()
                st.rerun()
    for e in errors:
        st.error(e)

    saved = [r for r in recs if r.get("residual")]
    if saved:
        st.subheader("📉 Inherent vs residual risk")
        st.dataframe(pd.DataFrame([{
            "Threat": r["matched_threat_id"], "Component / flow": r["component"],
            "Inherent": rec_risk(r), "Residual": rec_residual(r),
            "Reduction": rec_risk(r) - rec_residual(r), "Residual band": risk_band(rec_residual(r)),
            "Decision": r["residual"]["decision"], "Rationale": r["residual"]["rationale"]}
            for r in sorted(saved, key=lambda r: -rec_residual(r))]), use_container_width=True, hide_index=True)
        mc1, mc2 = st.columns(2)
        with mc1:
            st.markdown("**Before controls**")
            st.markdown(risk_matrix_html([(r["likelihood_n"], r["impact_n"], r["matched_threat_id"]) for r in saved]), unsafe_allow_html=True)
        with mc2:
            st.markdown("**After controls**")
            st.markdown(risk_matrix_html([(r["residual"]["likelihood_n"], r["residual"]["impact_n"], r["matched_threat_id"]) for r in saved]), unsafe_allow_html=True)
        tabs = st.tabs(["⚖️ Residual heat map", "🔥 Inherent heat map"])
        with tabs[0]:
            show_architecture_diagram(cfg, mode="residual", key_suffix="s10_res")
        with tabs[1]:
            show_architecture_diagram(cfg, mode="scoring", key_suffix="s10_inh")

    st.markdown("---")
    st.subheader("❓ Open questions and accepted risk")
    st.caption("List what you do not know and cannot fully control — dependencies, vendors, slow-moving threats, unverified assumptions.")
    third = [c["name"] for c in cfg["scenario"]["components"] if c["type"] == "external_entity" and _is_third_party(cfg, c)]
    st.button("💡 Insert example questions", key="w_oq_examples", on_click=_apply_oq_examples, args=(cfg,))
    qs = st.text_area("Open questions (one per line)", value="\n".join(oq["questions"]), key=f"w_oq_{st.session_state.selected_workshop}", height=130,
                      placeholder=f"e.g. What happens if {third[0] if third else 'a third-party provider'} is compromised?")
    acc = st.text_area("Accepted-risk statement", value=oq["accepted"], key=f"w_acc_{st.session_state.selected_workshop}", height=90,
                       placeholder="e.g. We accept that a determined attacker may slow a single endpoint, but we alert within 4 hours and can fail over.")
    newq, newa = _lines(qs), acc.strip()
    if newq != oq["questions"] or newa != oq["accepted"]:
        oq["questions"], oq["accepted"] = newq, newa
        save_progress()

    ready = bool(recs) and all(r.get("residual") for r in recs) and len(oq["questions"]) >= 1
    nav_buttons(9, "⬅️ Back to Controls", 11, "Next: Plan the review ➡️", ready,
                "Save residual risk for every threat and list at least one open question.", key="p10")


def _apply_oq_examples(cfg):
    ws = st.session_state.selected_workshop
    oq = get_open_questions(ws)
    third = [c["name"] for c in cfg["scenario"]["components"] if c["type"] == "external_entity" and _is_third_party(cfg, c)]
    ex = [f"What happens if {t} is compromised or changes its behaviour?" for t in third[:2]]
    ex += ["How quickly would we notice a slow, low-volume attack?", "Which assumptions from Step 1 are still unverified?",
           "How often do our dependencies change, and could an update introduce a vulnerability?"]
    if not oq["questions"]:
        oq["questions"] = ex
        st.session_state[f"w_oq_{ws}"] = "\n".join(ex)


# ═══════════════════════════════════════════════════════════════════════════════
#  PAGE 11 — REVIEW PLAN
# ═══════════════════════════════════════════════════════════════════════════════
FULL_TRIGGERS = ["New system or a high-risk launch", "Major architecture change",
                 "A feature gives a component new access to sensitive data or privileged actions",
                 "A new trust boundary is introduced", "Move to a new hosting platform or cloud region"]
LIGHT_CHECKS = ["What changed since the last review?", "Which trust boundaries moved?",
                "Were new endpoints, data stores, integrations or outputs introduced?",
                "Do existing controls still cover the risk?", "Are the Step 1 assumptions still true?"]
UPDATE_TRIGGERS = ["A dependency or platform has a major version change", "A component gains new permissions",
                   "A data source or third-party integration is added or changed", "A security incident occurs",
                   "A new attack technique becomes relevant", "Regulation or compliance requirements change",
                   "An assumption is found to be violated"]


def render_review_plan_page():
    ws = st.session_state.selected_workshop
    plan = get_review_plan(ws)
    st.header("Step 10: Schedule Reviews & Update Triggers")
    scope_reminder()
    st.markdown("""
    <div class="methodology-step">
    <strong>🔁 Stage 10 · Review</strong><br>
    A threat model is a <strong>living document</strong>, not a compliance artefact. Systems evolve too quickly for an annual ceremony,
    so use three levels of review. <strong>Ownership stays with product and engineering</strong> — security provides expertise and
    challenge, but the people building and running the system must keep the model useful. If it becomes paperwork theatre, teams route around it.
    </div>""", unsafe_allow_html=True)

    c1, c2 = st.columns(2)
    owner = c1.text_input("Owner (product / engineering)", value=plan["owner"], key=f"w_owner_{ws}", max_chars=80,
                          placeholder="e.g. Checkout team tech lead")
    sec = c2.text_input("Security's role", value=plan["security_role"], key=f"w_secrole_{ws}", max_chars=80)
    try:
        default_date = _date.fromisoformat(plan["next_review"]) if plan["next_review"] else _date.today() + _timedelta(days=30)
    except ValueError:
        default_date = _date.today() + _timedelta(days=30)
    nxt = st.date_input("Next lightweight review", value=default_date, key=f"w_nextrev_{ws}")

    st.markdown("### 1️⃣ Full workshop — when?")
    st.caption("A full workshop is for a new system, a high-risk launch, a major architecture change, or new access to sensitive data or tools.")
    full = st.multiselect("Triggers for a full workshop", FULL_TRIGGERS, default=[x for x in plan["full"] if x in FULL_TRIGGERS], key=f"w_full_{ws}")
    st.markdown("### 2️⃣ Lightweight review — what do you check? (≈30 minutes, for ordinary feature work)")
    light = st.multiselect("Lightweight review checklist", LIGHT_CHECKS, default=[x for x in plan["light"] if x in LIGHT_CHECKS], key=f"w_light_{ws}")
    st.markdown("### 3️⃣ Trigger-based update — what forces an update?")
    trig = st.multiselect("Update triggers", UPDATE_TRIGGERS, default=[x for x in plan["triggers"] if x in UPDATE_TRIGGERS], key=f"w_trig_{ws}")
    notes = st.text_input("How will you keep this from becoming paperwork?", value=plan["notes"], key=f"w_pnotes_{ws}", max_chars=200,
                          placeholder="e.g. Review is part of the sprint-planning checklist")

    new = {"owner": owner.strip(), "security_role": sec.strip(), "next_review": nxt.isoformat() if hasattr(nxt, "isoformat") else "",
           "full": list(full), "light": list(light), "triggers": list(trig), "notes": notes.strip()}
    if any(plan[k] != v for k, v in new.items()):
        plan.update(new)
        save_progress()

    st.markdown("---")
    st.subheader("✅ Threat-model readiness")
    status = stage_status()
    for sid, label, icon, done, detail in status:
        st.markdown(f"{'✅' if done else '⚠️'} {icon} **{label}** — {detail}")
    st.progress(sum(1 for s in status if s[3]) / len(status))

    nav_buttons(10, "⬅️ Back to Residual risk", 12, "Next: Assessment & report ➡️", status[-1][3],
                "Set an owner and choose at least one full-workshop trigger, one lightweight check and one update trigger.", key="p11")


# ═══════════════════════════════════════════════════════════════════════════════
#  PAGE 12 — STAGE-BY-STAGE REVIEW (replaces the old 4-step review)
# ═══════════════════════════════════════════════════════════════════════════════
def render_stage_summary():
    for sid, label, icon, done, detail in stage_status():
        bg = "#EFEFEE" if done else "#F6F5F4"
        clr = "#347737" if done else "#A6A196"
        st.markdown(f"""
        <div style="background:{bg};border-left:4px solid {clr};border-radius:8px;padding:12px 16px;margin:6px 0;display:flex;align-items:center;gap:12px">
          <span style="font-size:1.3em">{'✅' if done else '⭕'}</span>
          <div><strong style="color:{clr}">{icon} {label}</strong><br><span style="font-size:0.85em;color:#555">{_esc(detail)}</span></div>
        </div>""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════════
#  10-STAGE FLOW
#  Scope → Architecture → DFD → Trust boundaries → STRIDE → ATT&CK → Scoring → Controls → Residual risk → Review
#  Page ids (current_step) keep their original numbers; PAGE_ORDER defines the navigation sequence.
# ═══════════════════════════════════════════════════════════════════════════════
STAGES = [
    ("scope",    "Scope",            "📐"),
    ("arch",     "Architecture",     "🏛️"),
    ("dfd",      "DFD",              "🗺️"),
    ("trust",    "Trust boundaries", "🚧"),
    ("stride",   "STRIDE",           "⚡"),
    ("mitre",    "ATT&CK",           "🎯"),
    ("scoring",  "Scoring",          "📊"),
    ("controls", "Controls",         "🛡️"),
    ("residual", "Residual risk",    "⚖️"),
    ("review",   "Review",           "🔁"),
]
STAGE_IDS = [s[0] for s in STAGES]
PAGES = {
    1:  ("Scope & goals",         "scope"),
    14: ("Architecture",          "arch"),
    2:  ("Data-flow diagram",     "dfd"),
    15: ("Trust boundaries",      "trust"),
    3:  ("Zones of trust",        "trust"),
    16: ("Threat actors",         "stride"),
    4:  ("STRIDE rules",          "stride"),
    17: ("STRIDE mapping",        "stride"),
    5:  ("Attack tree",           "stride"),
    6:  ("Identify threats",      "stride"),
    18: ("MITRE ATT&CK mapping",  "mitre"),
    7:  ("Score the risk",        "scoring"),
    8:  ("OWASP mapping",         "controls"),
    9:  ("Select controls",       "controls"),
    10: ("Residual risk",         "residual"),
    11: ("Review plan",           "review"),
    12: ("Assessment & report",   "review"),
    13: ("Complete",              "review"),
}
PAGE_ORDER = [1, 14, 2, 15, 3, 16, 4, 17, 5, 6, 18, 7, 8, 9, 10, 11, 12, 13]


def nav_buttons(back_page, back_label, next_page, next_label, next_ok=True, block_msg="", key="nav"):
    """Back/next follow PAGE_ORDER; the page ids and labels passed by older call sites are ignored."""
    cur = int(st.session_state.current_step)
    i = PAGE_ORDER.index(cur) if cur in PAGE_ORDER else 0
    prev_p = PAGE_ORDER[i - 1] if (back_page is not None and i > 0) else None
    next_p = PAGE_ORDER[i + 1] if (next_page is not None and i + 1 < len(PAGE_ORDER)) else None
    st.markdown("---")
    c1, c2 = st.columns(2)
    with c1:
        if prev_p and st.button(f"⬅️ Back to {PAGES[prev_p][0]}", use_container_width=True, key=f"{key}_back"):
            go_page(prev_p)
    with c2:
        if next_p and st.button(f"Next: {PAGES[next_p][0]} ➡️", type="primary", use_container_width=True, key=f"{key}_next"):
            if next_ok:
                go_page(next_p)
            else:
                st.error(block_msg or "Complete this step first.")


# ═══════════════════════════════════════════════════════════════════════════════
#  MITRE ATT&CK (Enterprise v19: Defense Evasion was split into Stealth and Defense Impairment)
# ═══════════════════════════════════════════════════════════════════════════════
ATTACK_VERSION = "v19"
ATTACK_TACTICS = [
    ("TA0001", "Initial Access"), ("TA0002", "Execution"), ("TA0003", "Persistence"), ("TA0004", "Privilege Escalation"),
    ("TA0005", "Stealth"), ("TA0112", "Defense Impairment"), ("TA0006", "Credential Access"), ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"), ("TA0009", "Collection"), ("TA0011", "Command and Control"),
    ("TA0010", "Exfiltration"), ("TA0040", "Impact"),
]
ATTACK_MITIGATIONS = {
    "M1048": "Application Isolation and Sandboxing", "M1050": "Exploit Protection", "M1030": "Network Segmentation",
    "M1026": "Privileged Account Management", "M1051": "Update Software", "M1016": "Vulnerability Scanning",
    "M1032": "Multi-factor Authentication", "M1027": "Password Policies", "M1018": "User Account Management",
    "M1036": "Account Use Policies", "M1017": "User Training", "M1035": "Limit Access to Resource Over Network",
    "M1042": "Disable or Remove Feature or Program", "M1021": "Restrict Web-Based Content", "M1034": "Limit Hardware Installation",
    "M1038": "Execution Prevention", "M1047": "Audit", "M1022": "Restrict File and Directory Permissions",
    "M1041": "Encrypt Sensitive Information", "M1029": "Remote Data Storage", "M1054": "Software Configuration",
    "M1031": "Network Intrusion Prevention", "M1037": "Filter Network Traffic", "M1057": "Data Loss Prevention",
    "M1053": "Data Backup",
}


def _T(tid, name, tactics, stride, mits, hint, domain="Enterprise"):
    return {"id": tid, "name": name, "tactics": tactics, "stride": stride, "m": mits, "hint": hint, "domain": domain}


ATTACK_TECHNIQUES = [
    _T("T1190", "Exploit Public-Facing Application", ["Initial Access"], "TIE", ["M1048", "M1050", "M1030", "M1026", "M1051", "M1016"], "Patch and harden internet-facing apps; validate all input."),
    _T("T1078", "Valid Accounts", ["Initial Access", "Persistence", "Privilege Escalation"], "SE", ["M1032", "M1027", "M1026", "M1018", "M1036", "M1017"], "Stolen or default credentials make the attacker look legitimate."),
    _T("T1566", "Phishing", ["Initial Access"], "S", ["M1017"], "Train users, filter email and verify senders."),
    _T("T1199", "Trusted Relationship", ["Initial Access"], "SE", ["M1030", "M1032", "M1018"], "A compromised partner or vendor connection becomes the way in."),
    _T("T1195", "Supply Chain Compromise", ["Initial Access"], "T", ["M1051", "M1016"], "Verify dependencies, build pipelines and update channels."),
    _T("T1133", "External Remote Services", ["Initial Access", "Persistence"], "S", ["M1032", "M1030", "M1042", "M1035"], "Expose remote access only through MFA-protected, segmented paths."),
    _T("T1189", "Drive-by Compromise", ["Initial Access"], "TE", ["M1048", "M1050", "M1051", "M1021"], "Harden browsers and restrict web content."),
    _T("T1200", "Hardware Additions", ["Initial Access"], "ST", ["M1034"], "Control which devices may attach or enrol."),
    _T("T1059", "Command and Scripting Interpreter", ["Execution"], "TE", ["M1038", "M1026", "M1042"], "Restrict interpreters and never pass user input to a shell."),
    _T("T1203", "Exploitation for Client Execution", ["Execution"], "TE", ["M1048", "M1050", "M1051"], "Keep clients patched and sandboxed."),
    _T("T1505", "Server Software Component", ["Persistence"], "TE", ["M1047", "M1026", "M1022"], "Monitor and lock down server extensions (for example web shells)."),
    _T("T1098", "Account Manipulation", ["Persistence", "Privilege Escalation"], "E", ["M1032", "M1026", "M1018"], "Alert on permission and credential changes."),
    _T("T1136", "Create Account", ["Persistence"], "SE", ["M1032", "M1026", "M1018"], "Control and audit account creation."),
    _T("T1068", "Exploitation for Privilege Escalation", ["Privilege Escalation"], "E", ["M1048", "M1050", "M1051", "M1016"], "Patch, sandbox and scan for vulnerable components."),
    _T("T1548", "Abuse Elevation Control Mechanism", ["Privilege Escalation"], "E", ["M1026", "M1022", "M1047"], "Enforce least privilege and audit elevation."),
    _T("T1134", "Access Token Manipulation", ["Privilege Escalation"], "SE", ["M1026", "M1018"], "Limit who can mint or impersonate tokens."),
    _T("T1611", "Escape to Host", ["Privilege Escalation"], "E", ["M1048", "M1038", "M1026"], "Isolate containers and drop unnecessary privileges."),
    _T("T1070", "Indicator Removal", ["Stealth"], "R", ["M1041", "M1029", "M1022"], "Forward logs off-host quickly and protect them with permissions."),
    _T("T1685", "Disable or Modify Tools", ["Defense Impairment"], "R", [], "Protect logging and security tooling; alert when it stops reporting (this includes clearing or disabling logs)."),
    _T("T1689", "Downgrade Attack", ["Defense Impairment"], "TI", [], "Disable legacy protocol and cipher fallback (for example TLS downgrade)."),
    _T("T1599", "Network Boundary Bridging", ["Defense Impairment"], "TE", ["M1030"], "Protect the devices that separate trusted and untrusted networks."),
    _T("T1556", "Modify Authentication Process", ["Credential Access", "Persistence", "Defense Impairment"], "SE", ["M1032", "M1026", "M1047"], "Protect and audit the authentication path."),
    _T("T1553", "Subvert Trust Controls", ["Defense Impairment"], "ST", [], "Protect signing keys; enforce certificate and code-signing validation."),
    _T("T1110", "Brute Force", ["Credential Access"], "S", ["M1032", "M1036", "M1027", "M1018"], "Lock out, rate-limit and require MFA."),
    _T("T1528", "Steal Application Access Token", ["Credential Access"], "SI", ["M1032", "M1018", "M1017"], "Short-lived, scoped tokens; monitor consent and usage."),
    _T("T1539", "Steal Web Session Cookie", ["Credential Access"], "SI", ["M1017", "M1054"], "Harden session cookies (HttpOnly, Secure, SameSite) and expiry."),
    _T("T1552", "Unsecured Credentials", ["Credential Access"], "I", ["M1041", "M1027", "M1022", "M1047"], "Keep secrets in a vault, never in code, config or logs."),
    _T("T1555", "Credentials from Password Stores", ["Credential Access"], "I", ["M1027"], "Protect and rotate credential stores."),
    _T("T1606", "Forge Web Credentials", ["Credential Access"], "S", ["M1047", "M1026"], "Protect signing keys and validate tokens strictly."),
    _T("T1557", "Adversary-in-the-Middle", ["Credential Access", "Collection"], "STI", ["M1041", "M1030", "M1031"], "Encrypt and authenticate traffic end to end."),
    _T("T1040", "Network Sniffing", ["Credential Access", "Discovery"], "I", ["M1041"], "Encrypt data in transit."),
    _T("T1087", "Account Discovery", ["Discovery"], "I", [], "Limit directory and user enumeration."),
    _T("T1046", "Network Service Discovery", ["Discovery"], "I", ["M1030", "M1031"], "Segment networks and detect scanning."),
    _T("T1021", "Remote Services", ["Lateral Movement"], "SE", ["M1032", "M1030", "M1035"], "Restrict remote services between zones; require MFA."),
    _T("T1550", "Use Alternate Authentication Material", ["Lateral Movement"], "S", ["M1026", "M1018"], "Short-lived credentials and token binding."),
    _T("T1530", "Data from Cloud Storage", ["Collection"], "I", ["M1047", "M1041", "M1032", "M1018"], "Private buckets, least privilege and access logging."),
    _T("T1213", "Data from Information Repositories", ["Collection"], "I", ["M1047", "M1018"], "Restrict and audit access to wikis, tickets and shared repositories."),
    _T("T1005", "Data from Local System", ["Collection"], "I", ["M1057"], "Encrypt local data; apply data-loss prevention."),
    _T("T1119", "Automated Collection", ["Collection"], "I", [], "Rate limits and anomaly detection on bulk access."),
    _T("T1114", "Email Collection", ["Collection"], "I", ["M1032"], "Protect mail access with MFA and audit rules."),
    _T("T1185", "Browser Session Hijacking", ["Collection"], "STI", ["M1017"], "Short sessions, re-authentication for sensitive actions."),
    _T("T1041", "Exfiltration Over C2 Channel", ["Exfiltration"], "I", ["M1031"], "Monitor and filter outbound traffic."),
    _T("T1567", "Exfiltration Over Web Service", ["Exfiltration"], "I", ["M1021"], "Restrict outbound web destinations."),
    _T("T1048", "Exfiltration Over Alternative Protocol", ["Exfiltration"], "I", ["M1037", "M1031", "M1030"], "Egress filtering and protocol allow-lists."),
    _T("T1537", "Transfer Data to Cloud Account", ["Exfiltration"], "I", [], "Restrict cross-account sharing; alert on snapshots and copies."),
    _T("T1499", "Endpoint Denial of Service", ["Impact"], "D", ["M1037"], "Rate limiting, quotas and request-cost limits."),
    _T("T1498", "Network Denial of Service", ["Impact"], "D", ["M1037"], "Upstream filtering and capacity planning."),
    _T("T1496", "Resource Hijacking", ["Impact"], "D", [], "Quotas, budget alerts and workload monitoring."),
    _T("T1489", "Service Stop", ["Impact"], "D", ["M1022", "M1018"], "Protect service control; alert on stopped services."),
    _T("T1485", "Data Destruction", ["Impact"], "DT", ["M1053"], "Tested, isolated backups."),
    _T("T1486", "Data Encrypted for Impact", ["Impact"], "D", ["M1053"], "Offline backups and tested recovery."),
    _T("T1531", "Account Access Removal", ["Impact"], "D", [], "Protect admin accounts; alert on mass password resets or deletions."),
    _T("T1565", "Data Manipulation", ["Impact"], "T", ["M1041", "M1030", "M1022"], "Integrity checks, signing and strict write permissions (includes stored and transmitted data)."),
    _T("T1491", "Defacement", ["Impact"], "T", ["M1053"], "Integrity monitoring and restorable content."),
    _T("T1657", "Financial Theft", ["Impact"], "TS", [], "Out-of-band verification for payment changes; transaction monitoring."),
    # ICS-domain techniques that matter for connected medical / IoT devices (new naming in v19)
    _T("T1692", "Unauthorized Message", ["ICS"], "ST", [], "Authenticate and integrity-protect device commands and reports.", "ICS"),
    _T("T1693", "Modify Firmware", ["ICS"], "T", [], "Signed firmware and secure boot.", "ICS"),
    _T("T1694", "Insecure Credentials", ["ICS"], "S", [], "No default or hard-coded device credentials.", "ICS"),
    _T("T1691", "Block Operational Technology Message", ["ICS"], "D", [], "Detect missing or blocked device messages.", "ICS"),
    _T("T1695", "Block Communications", ["ICS"], "D", [], "Redundant paths and heartbeat monitoring.", "ICS"),
]
ATTACK_BY_ID = {t["id"]: t for t in ATTACK_TECHNIQUES}


def attack_label(t, aligned=False):
    return f"{'⭐ ' if aligned else ''}{t['id']} · {t['name']} — {' / '.join(t['tactics'])}"


def attack_mitigation_hints(rec):
    out = {}
    for tid in rec.get("mitre", []):
        t = ATTACK_BY_ID.get(tid)
        if not t:
            continue
        for m in t["m"]:
            out[m] = ATTACK_MITIGATIONS[m]
        if not t["m"]:
            out[tid] = t["hint"]
    return out


# ═══════════════════════════════════════════════════════════════════════════════
#  THREAT ACTOR CATALOG
# ═══════════════════════════════════════════════════════════════════════════════
ACTOR_CATALOG = [
    {"name": "External attacker (opportunistic)", "capability": "Low", "motivation": "Financial gain, vandalism", "entry": "public"},
    {"name": "Malicious or compromised user", "capability": "Medium", "motivation": "Fraud or data theft using legitimate access", "entry": "public"},
    {"name": "Skilled external attacker (targeted)", "capability": "High", "motivation": "Targeted data theft or extortion", "entry": "public"},
    {"name": "Adversary with network access", "capability": "Medium", "motivation": "Intercept or alter data in transit", "entry": "flows"},
    {"name": "Malicious insider / privileged admin", "capability": "High", "motivation": "Abuse of privileged access", "entry": "internal"},
    {"name": "Compromised third party / supply chain", "capability": "Medium", "motivation": "Pivot through a trusted integration", "entry": "third_party"},
    {"name": "Adversary with physical or device access", "capability": "Medium", "motivation": "Tamper with or extract from devices", "entry": "device"},
    {"name": "Automated bot / botnet", "capability": "Low", "motivation": "Credential stuffing, scraping, denial of service", "entry": "public"},
]


def suggest_entries(kind, cfg):
    comps = cfg["scenario"]["components"]
    third = third_party_components(cfg)
    zs = {c["name"]: c.get("zone_score", 3) for c in comps}
    cross = [k for k, v in flow_crossings(cfg).items() if v]
    if kind == "public":
        return [c["name"] for c in comps if (c["type"] == "external_entity" and c["name"] not in third)
                or (c["type"] == "process" and zs[c["name"]] <= 2)][:3]
    if kind == "flows":
        return cross[:2]
    if kind == "internal":
        return [c["name"] for c in comps if c["type"] != "external_entity" and zs[c["name"]] >= 5][:2]
    if kind == "third_party":
        return [c["name"] for c in comps if c["name"] in third][:2]
    if kind == "device":
        return [c["name"] for c in comps if c["type"] != "datastore" and zs[c["name"]] <= 1][:2]
    return []


def get_actors(ws_id=None):
    return [a for a in get_annotations(ws_id) if a["kind"] == "actor"]


def boundary_checked(ws_id=None):
    ws_id = ws_id or st.session_state.selected_workshop
    return bool(st.session_state.boundary_checked.get(ws_id))


def zone_rule_expectation(cfg, f):
    zs = {c["name"]: c.get("zone_score", 3) for c in cfg["scenario"]["components"]}
    sz, dz = zs.get(f["source"], 3), zs.get(f["destination"], 3)
    letters = ""
    if sz < dz:
        letters += "T"
    if sz > dz:
        letters += "I"
    if sz == 0:
        letters += "D"
    return letters


def element_rows(cfg):
    scn = cfg["scenario"]
    eid = element_ids(scn)
    cross = flow_crossings(cfg)
    rows = []
    for c in scn["components"]:
        rows.append({"key": c["name"], "id": eid[c["name"]], "name": c["name"], "kind": c["type"], "cross": ""})
    for f in scn["data_flows"]:
        k = _flow_key(f)
        rows.append({"key": k, "id": eid[k], "name": k, "kind": "flow", "cross": ", ".join(cross.get(k, []))})
    return rows


KIND_LABEL = {"external_entity": "External entity", "process": "Process", "datastore": "Data store", "flow": "Data flow"}


def stride_applicability_html():
    head = "".join(f'<th style="padding:4px 10px;color:white;background:{_STRIDE_TAG_COLOR[l]}">{l}</th>' for l in STRIDE_LETTERS)
    rows = []
    for kind in ("external_entity", "process", "datastore", "flow"):
        cells = "".join(f'<td style="text-align:center;padding:4px 10px;border:1px solid #E9E8E6">{"✔" if l in STRIDE_PER_ELEMENT[kind] else "·"}</td>' for l in STRIDE_LETTERS)
        rows.append(f'<tr><td style="padding:4px 10px;border:1px solid #E9E8E6;font-weight:600">{KIND_LABEL[kind]}</td>{cells}</tr>')
    names = "".join(f'<td style="font-size:0.72em;color:#80796B;text-align:center">{STRIDE_NAMES[l].split()[0]}</td>' for l in STRIDE_LETTERS)
    return (f'<table style="border-collapse:collapse;font-size:0.85em"><tr><th></th>{head}</tr><tr><td></td>{names}</tr>{"".join(rows)}</table>')


# ═══════════════════════════════════════════════════════════════════════════════
#  PAGE 14 — ARCHITECTURE
# ═══════════════════════════════════════════════════════════════════════════════
def render_architecture_page():
    ws = st.session_state.selected_workshop
    cfg = current_workshop
    s = cfg["scenario"]
    items = get_annotations(ws)
    st.header("Step 2: Architecture — What Runs Where?")
    scope_reminder()
    st.markdown("""
    <div class="methodology-step">
    <strong>🏛️ Stage 2 · Architecture</strong><br>
    Start from the system as it is <strong>built and deployed</strong>: which components exist, which environment each one runs in
    (device, cloud, partner network…) and which <strong>assets</strong> live where. The next stages simplify this picture into a
    data-flow diagram, then draw trust boundaries on it. Label the assets you care about now — they will follow you through the whole model.
    </div>""", unsafe_allow_html=True)

    show_architecture_diagram(cfg, mode="architecture", key_suffix="s14_arch", editable=True, default_kind="asset")

    st.subheader("📦 Component inventory")
    paths = component_boundaries(cfg)
    st.dataframe(pd.DataFrame([{"Component": c["name"], "Type": KIND_LABEL[c["type"]], "Runs in": " › ".join(paths.get(c["name"], [])),
                                "What it is": c["description"]} for c in s["components"]]), use_container_width=True, hide_index=True)

    st.subheader("💎 Where do the assets live?")
    st.caption("Map each asset from the scenario to the component or data flow that holds or carries it. This creates asset labels (A01, A02…) on the diagram.")
    targets = [c["name"] for c in s["components"]] + list(dict.fromkeys(_flow_key(f) for f in s["data_flows"]))
    existing = {i.get("origin"): i for i in items if i["kind"] == "asset" and i.get("origin")}
    with st.form("asset_map_form"):
        picks = {}
        for idx, asset in enumerate(s.get("assets", [])):
            cur = existing.get(f"asset:{asset}", {}).get("target")
            opts = ["— not mapped —"] + targets
            picks[asset] = st.selectbox(asset, opts, index=opts.index(cur) if cur in opts else 0, key=f"w_asset_{ws}_{idx}")
        if st.form_submit_button("💎 Save asset map", type="primary"):
            for asset, tgt in picks.items():
                origin = f"asset:{asset}"
                if tgt == "— not mapped —":
                    items[:] = [i for i in items if i.get("origin") != origin]
                elif origin in existing:
                    existing[origin]["target"] = tgt
                else:
                    items.append({"id": _next_annotation_id(items, "asset"), "kind": "asset", "label": asset, "target": tgt,
                                  "links": [], "notes": "", "origin": origin})
            save_progress()
            st.rerun()
    n_assets = sum(1 for i in items if i["kind"] == "asset")
    nav_buttons(1, "", 2, "", n_assets >= 2, "Label at least two assets (use the asset map above or the label editor).", key="p14")


# ═══════════════════════════════════════════════════════════════════════════════
#  PAGE 15 — TRUST BOUNDARIES
# ═══════════════════════════════════════════════════════════════════════════════
def render_trust_boundary_page():
    ws = st.session_state.selected_workshop
    cfg = current_workshop
    s = cfg["scenario"]
    st.header("Step 4: Trust Boundaries")
    scope_reminder()
    st.markdown("""
    <div class="methodology-step">
    <strong>🚧 Stage 4 · Trust boundaries</strong><br>
    A trust boundary is a line where the <strong>level of trust changes</strong> — device to cloud, internet to your network, your code to a
    vendor. Every data flow that crosses one needs authentication, validation and protection, so these crossings are where the STRIDE analysis
    concentrates. Dashed boxes below are the boundaries; red dashed flows cross at least one (● shows where).
    </div>""", unsafe_allow_html=True)
    show_architecture_diagram(cfg, mode="boundaries", key_suffix="s15_tb")

    lay = layout_tree(cfg)
    cross = flow_crossings(cfg)
    eid = element_ids(s)
    st.subheader("🧱 Boundaries")
    rows = []
    for g in sorted(lay["groups"], key=lambda r: (r["depth"], r["x"])):
        inside = [n for n, r in lay["leaves"].items() if g["name"] in r["path"]]
        n_cross = sum(1 for k, v in cross.items() if g["name"] in v)
        rows.append({"Boundary": ("   " * g["depth"]) + g["name"], "Trust level": g["trust"] or "—", "Contains": ", ".join(inside),
                     "Flows crossing it": n_cross})
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    st.subheader("🎯 Which flows cross a trust boundary?")
    st.caption("Select every data flow that crosses at least one boundary. Use the diagram: a flow crosses when its two ends sit in different boxes.")
    flow_opts = [f"{eid[_flow_key(f)]} · {_flow_key(f)}" for f in s["data_flows"]]
    truth = {f"{eid[k]} · {k}" for k, v in cross.items() if v}
    with st.form("boundary_check_form"):
        picked = st.multiselect("Flows that cross a trust boundary", flow_opts, key=f"w_xflows_{ws}")
        if st.form_submit_button("Check my answer", type="primary"):
            st.session_state.boundary_checked[ws] = True
            save_progress()
            tp, fp, fn = len(set(picked) & truth), len(set(picked) - truth), len(truth - set(picked))
            if fp == 0 and fn == 0:
                st.success("✅ Exactly right — every one of those flows needs explicit controls and a STRIDE look.")
            else:
                if fn:
                    st.warning("Missed: " + "; ".join(sorted(truth - set(picked))))
                if fp:
                    st.warning("These stay inside one boundary: " + "; ".join(sorted(set(picked) - truth)))
    st.subheader("📋 Boundary-crossing flows")
    st.dataframe(pd.DataFrame([{"ID": eid[k], "Flow": k, "Crosses": ", ".join(v) if v else "— (stays inside one boundary)",
                                "# boundaries": len(v)} for k, v in sorted(cross.items(), key=lambda kv: -len(kv[1]))]),
                 use_container_width=True, hide_index=True)
    nav_buttons(2, "", 3, "", boundary_checked(ws), "Press “Check my answer” on the boundary-crossing exercise first.", key="p15")


# ═══════════════════════════════════════════════════════════════════════════════
#  PAGE 16 — THREAT ACTORS
# ═══════════════════════════════════════════════════════════════════════════════
def render_threat_actors_page():
    ws = st.session_state.selected_workshop
    cfg = current_workshop
    s = cfg["scenario"]
    items = get_annotations(ws)
    st.header("Step 5: Threat Actors — Who Would Attack, and Where Do They Get In?")
    scope_reminder()
    st.markdown("""
    <div class="methodology-step">
    <strong>🎭 Stage 5 · STRIDE — part 1: threat actors</strong><br>
    STRIDE finds <em>what can go wrong</em>; threat actors explain <em>who</em> would make it go wrong and <em>where they enter</em>.
    For each actor note their <strong>capability</strong> and <strong>motivation</strong>, then map them to the <strong>entry points</strong> they can reach first.
    Actors appear as devils outside your system; later every threat scenario (TS) you identify is linked to the actor behind it.
    </div>""", unsafe_allow_html=True)

    targets = [c["name"] for c in s["components"]] + list(dict.fromkeys(_flow_key(f) for f in s["data_flows"]))
    profiles = [p["name"] for p in ACTOR_CATALOG] + ["Custom actor…"]
    c1, c2 = st.columns([3, 2])
    with c1:
        prof = st.selectbox("Actor profile", profiles, key=f"w_actprof_{ws}")
        pidx = profiles.index(prof)
        base = ACTOR_CATALOG[pidx] if pidx < len(ACTOR_CATALOG) else {"name": "", "capability": "Medium", "motivation": "", "entry": ""}
        name = prof if pidx < len(ACTOR_CATALOG) else st.text_input("Name of the custom actor", key=f"w_actname_{ws}", max_chars=70)
        motive = st.text_input("Motivation", value=base["motivation"], key=f"w_actmot_{ws}_{pidx}", max_chars=120)
    with c2:
        cap = st.select_slider("Capability", LEVELS, value=base["capability"], key=f"w_actcap_{ws}_{pidx}")
        st.caption("Low: opportunistic, public tools · Medium: skilled, some access · High: well-resourced or privileged.")
    sugg = [t for t in suggest_entries(base.get("entry", ""), cfg) if t in targets]
    entries = st.multiselect("Entry points (first one is the main arrow; add more if the actor can reach several)", targets,
                             default=sugg, key=f"w_actent_{ws}_{pidx}")
    if st.button("➕ Add threat actor", type="primary", key="w_actadd"):
        if not (name or "").strip():
            st.warning("Give the actor a name.")
        elif not entries:
            st.warning("Choose at least one entry point.")
        else:
            items.append({"id": _next_annotation_id(items, "actor"), "kind": "actor", "label": name.strip(), "target": entries[0],
                          "entries": list(entries[1:]), "links": [], "notes": motive.strip(), "capability": cap})
            save_progress()
            st.rerun()

    actors = get_actors(ws)
    if actors:
        st.subheader("🎭 Your threat actors")
        for a in sorted(actors, key=_ann_sort):
            x1, x2, x3, x4 = st.columns([1, 4, 5, 1])
            x1.markdown(f"**{a['id']}**")
            x2.text(f"{a['label']} ({a.get('capability', '—')})")
            x3.text("→ " + ", ".join(_actor_targets(a)))
            if x4.button("🗑", key=f"w_actdel_{a['id']}", help=f"Remove {a['id']}"):
                items[:] = [i for i in items if i["id"] != a["id"]]
                for i in items:
                    i["links"] = [l for l in i.get("links", []) if l != a["id"]]
                save_progress()
                st.rerun()
    show_architecture_diagram(cfg, mode="actors", key_suffix="s16_act", editable=True, default_kind="actor")
    ok = len(actors) >= 2 and all(a["target"] for a in actors)
    nav_buttons(15, "", 4, "", ok, "Add at least two threat actors, each with an entry point.", key="p16")


# ═══════════════════════════════════════════════════════════════════════════════
#  PAGE 17 — STRIDE MAPPING (aligned with the architecture)
# ═══════════════════════════════════════════════════════════════════════════════
def render_stride_mapping_page():
    ws = st.session_state.selected_workshop
    cfg = current_workshop
    s = cfg["scenario"]
    smap = get_stride_map(ws)
    rows = element_rows(cfg)
    st.header("Step 5 (cont.): STRIDE Mapping on the Architecture")
    scope_reminder()
    st.markdown("""
    <div class="methodology-step">
    <strong>⚡ Stage 5 · STRIDE — part 2: map STRIDE to every element</strong><br>
    Walk the diagram element by element (STRIDE-per-element). Tick the categories that <em>realistically apply</em> to each external entity,
    process, data store and data flow — concentrating on flows that <strong>cross a trust boundary</strong>. Your ticks appear as coloured
    letters on the architecture, next to the threat actors who would exploit them.
    </div>""", unsafe_allow_html=True)
    with st.expander("📘 Which STRIDE categories can apply to which element?", expanded=False):
        st.markdown(stride_applicability_html(), unsafe_allow_html=True)
        for k, v in STRIDE_ELEMENT_NOTE.items():
            st.markdown(f"- **{KIND_LABEL[k]}** — {v}")

    cols = ["ID", "Element", "Kind", "Crosses boundary"] + STRIDE_LETTERS
    seed_rows = []
    for r in rows:
        cur = smap.get(r["key"], [])
        seed_rows.append({"ID": r["id"], "Element": r["name"], "Kind": KIND_LABEL[r["kind"]],
                          "Crosses boundary": ("✔ " + r["cross"]) if r["cross"] else "—", **{l: (l in cur) for l in STRIDE_LETTERS}})
    sk = f"_seed_stride_{ws}"
    if sk not in st.session_state:
        st.session_state[sk] = pd.DataFrame(seed_rows, columns=cols)
    cfgcols = {l: st.column_config.CheckboxColumn(l, help=STRIDE_NAMES[l], default=False) for l in STRIDE_LETTERS}
    df = st.data_editor(st.session_state[sk], key=f"w_ed_stride_{ws}", hide_index=True, use_container_width=True,
                        disabled=["ID", "Element", "Kind", "Crosses boundary"], column_config=cfgcols)
    new_map, invalid = {}, []
    by_name = {r["name"]: r for r in rows}
    for rec in df.to_dict("records"):
        r = by_name.get(rec["Element"])
        if not r:
            continue
        ticked = [l for l in STRIDE_LETTERS if rec.get(l)]
        ok_l = [l for l in ticked if l in STRIDE_PER_ELEMENT[r["kind"]]]
        bad = [l for l in ticked if l not in STRIDE_PER_ELEMENT[r["kind"]]]
        if bad:
            invalid.append((r["id"], r["name"], bad, r["kind"]))
        if ok_l:
            new_map[r["key"]] = ok_l
    if new_map != smap:
        st.session_state.stride_map[ws] = new_map
        smap = new_map
        save_progress()
    for rid, nm, bad, kind in invalid:
        st.warning(f"{rid} {nm}: {', '.join(STRIDE_NAMES[b] for b in bad)} do(es) not apply to a {KIND_LABEL[kind].lower()} "
                   "and is ignored on the diagram. " + STRIDE_ELEMENT_NOTE[kind])

    mapped = sum(1 for r in rows if smap.get(r["key"]))
    crossing = [r for r in rows if r["kind"] == "flow" and r["cross"]]
    missing_cross = [r["id"] for r in crossing if not smap.get(r["key"])]
    st.progress(mapped / len(rows))
    st.caption(f"{mapped}/{len(rows)} elements mapped · {len(crossing) - len(missing_cross)}/{len(crossing)} boundary-crossing flows mapped")
    if missing_cross:
        st.info("Boundary-crossing flows still unmapped: " + ", ".join(missing_cross))

    flows = [r for r in rows if r["kind"] == "flow"]
    if any(smap.get(r["key"]) for r in flows):
        st.subheader("🧭 Compare with the zone-direction rules")
        fl = {_flow_key(f): f for f in s["data_flows"]}
        table = []
        for r in flows:
            exp = zone_rule_expectation(cfg, fl[r["key"]])
            got = "".join(smap.get(r["key"], []))
            table.append({"ID": r["id"], "Flow": r["name"], "Zone rule expects": exp or "same zone", "You mapped": got or "—",
                          "Match": "✅" if (not exp or set(exp) <= set(got)) else "⚠️ review"})
        st.dataframe(pd.DataFrame(table), use_container_width=True, hide_index=True)
        st.caption("T = data flows from a lower to a higher zone · I = from a higher to a lower zone · D = the source is an untrusted Zone-0 entity.")

    show_architecture_diagram(cfg, mode="stride", key_suffix="s17_stride", editable=True, default_kind="threat")
    ok = mapped >= max(1, int(0.6 * len(rows))) and not missing_cross
    nav_buttons(16, "", 5, "", ok, "Map at least 60% of the elements and every boundary-crossing flow.", key="p17")


# ═══════════════════════════════════════════════════════════════════════════════
#  PAGE 18 — MITRE ATT&CK MAPPING
# ═══════════════════════════════════════════════════════════════════════════════
def attack_matrix_html(records):
    cols = [t for _, t in ATTACK_TACTICS] + ["ICS"]
    cells = {c: [] for c in cols}
    for r in records:
        for tid in r.get("mitre", []):
            t = ATTACK_BY_ID.get(tid)
            if not t:
                continue
            for tac in t["tactics"]:
                if tac in cells:
                    cells[tac].append((tid, r["matched_threat_id"]))
    head = "".join(f'<th style="padding:6px 8px;background:{"#3E897F" if cells[c] else "#EFEFEE"};color:{"white" if cells[c] else "#948D80"};'
                   f'font-size:0.72em;min-width:92px;border:1px solid #fff">{_esc(c)}</th>' for c in cols)
    body = "".join(
        f'<td style="vertical-align:top;padding:6px;border:1px solid #E9E8E6;background:{"#F5F4F3" if cells[c] else "#FAFAFA"};font-size:0.75em">'
        + ("<br>".join(f'<b>{_esc(tid)}</b> <span style="color:#948D80">({_esc(th)})</span>' for tid, th in sorted(set(cells[c]))) or "&nbsp;")
        + "</td>" for c in cols)
    return f'<div style="overflow-x:auto"><table style="border-collapse:collapse"><tr>{head}</tr><tr>{body}</tr></table></div>'


def render_mitre_page():
    cfg = current_workshop
    recs = st.session_state.user_answers
    st.header("Step 6: Map Your Threats to MITRE ATT&CK")
    scope_reminder()
    st.markdown(f"""
    <div class="methodology-step">
    <strong>🎯 Stage 6 · MITRE ATT&amp;CK ({ATTACK_VERSION})</strong><br>
    STRIDE tells you <em>what</em> can go wrong; ATT&amp;CK describes <em>how real adversaries do it</em>. For every threat you identified, pick the
    <strong>techniques</strong> an attacker would use — they belong to <strong>tactics</strong> (the attacker's goal at each step of an attack).
    Map only techniques supported by the scenario and document the attack path. Do not force a mapping when ATT&CK does not fit; one technique may be sufficient.
    <br><br>
    <em>Note:</em> in ATT&amp;CK v19 (April 2026) the old <b>Defense Evasion</b> tactic was split into <b>Stealth</b> (staying hidden) and
    <b>Defense Impairment</b> (breaking defences), so log tampering is now under Defense Impairment.
    </div>""", unsafe_allow_html=True)
    if not recs:
        st.warning("Identify threats first (STRIDE stage).")
        nav_buttons(6, "", None, "", key="p18e")
        return

    with st.form("mitre_form"):
        vals = {}
        for rec in recs:
            pred = rec["predefined_threat"]
            letter = STRIDE_LETTER_OF.get(rec["stride"], "")
            ordered = sorted(ATTACK_TECHNIQUES, key=lambda t: (letter not in t["stride"], t["domain"] != "Enterprise", t["id"]))
            labels = {attack_label(t, letter in t["stride"]): t["id"] for t in ordered}
            st.markdown(f"**{pred['id']} · {rec['stride']} on {rec['component']}**")
            st.caption(pred["threat"] + "   (⭐ = technique commonly associated with this STRIDE category)")
            cur = [lbl for lbl, tid in labels.items() if tid in rec.get("mitre", [])]
            vals[pred["id"]] = (st.multiselect("ATT&CK technique(s) supported by the scenario (leave empty if none fit)", list(labels.keys()), default=cur, key=f"w_mitre_{pred['id']}"), labels,
                                st.text_input("Attack path / justification (explain a non-mapping if no technique fits)",
                                              value=rec.get("mitre_note", ""), key=f"w_mnote_{pred['id']}", max_chars=300),
                                st.selectbox("Candidate CAPEC attack pattern", ["— not assessed —"] + list(CAPEC_CANDIDATES),
                                              index=((["— not assessed —"] + list(CAPEC_CANDIDATES)).index(rec.get("capec", [""])[0]) if rec.get("capec") and rec.get("capec", [""])[0] in (["— not assessed —"] + list(CAPEC_CANDIDATES)) else 0),
                                              key=f"w_capec_{pred['id']}"),
                                st.text_input("CAPEC fit rationale (or why none is suitable)", value=rec.get("capec_rationale", ""),
                                              max_chars=300, key=f"w_capecwhy_{pred['id']}"))
            st.markdown("---")
        if st.form_submit_button("🎯 Save ATT&CK mapping", type="primary", use_container_width=True):
            for rec in recs:
                sel, labels, note, capec_choice, capec_rationale = vals[rec["matched_threat_id"]]
                rec["mitre"] = [labels[x] for x in sel if x in labels]
                rec["mitre_note"] = (note or "").strip()
                rec["capec"] = [] if capec_choice == "— not assessed —" else [capec_choice]
                rec["capec_rationale"] = (capec_rationale or "").strip()
            save_progress()
            st.rerun()

    mapped = [r for r in recs if r.get("mitre")]
    if mapped:
        st.subheader("🧩 ATT&CK matrix coverage")
        st.markdown(attack_matrix_html(mapped), unsafe_allow_html=True)
        st.subheader("🔎 Alignment check")
        for rec in mapped:
            letter = STRIDE_LETTER_OF.get(rec["stride"], "")
            techs = [ATTACK_BY_ID[t] for t in rec["mitre"] if t in ATTACK_BY_ID]
            tactics = sorted({tac for t in techs for tac in t["tactics"]})
            weak = [t["id"] for t in techs if letter not in t["stride"]]
            with st.expander(f"{rec['matched_threat_id']} — {', '.join(t['id'] for t in techs)}"):
                if weak:
                    st.warning(f"Weak fit with {rec['stride']}: {', '.join(weak)}. That is fine if the technique is a step in the attack path rather than the end goal.")
                else:
                    st.success(f"Every technique is commonly associated with {rec['stride']}.")
                if len([t for t in tactics if t != 'ICS']) < 2:
                    st.info("Consider adding a technique from a second tactic (for example how the attacker gets in, then what they achieve).")
                st.markdown("**Tactics covered:** " + (", ".join(tactics) or "—"))
                for t in techs:
                    st.markdown(f"- **{t['id']} {t['name']}** ({', '.join(t['tactics'])}) — {t['hint']}")
                hints = attack_mitigation_hints(rec)
                mits = [f"{k} {v}" for k, v in hints.items() if k.startswith("M")]
                if mits:
                    st.markdown("**ATT&CK mitigations:** " + "; ".join(mits))
        show_architecture_diagram(cfg, mode="mitre", key_suffix="s18_mitre")
    mapped_or_explained = bool(recs) and all(r.get("mitre") or (r.get("mitre_note", "").strip() and "no suitable" in r.get("mitre_note", "").lower()) for r in recs)
    nav_buttons(6, "", 7, "", mapped_or_explained,
                "Map a supported ATT&CK technique, or write “No suitable ATT&CK technique” and explain why in the attack-path field.", key="p18")


# ═══════════════════════════════════════════════════════════════════════════════
#  REPLACEMENTS: identified threats, label sync, status, review, PDF extras
# ═══════════════════════════════════════════════════════════════════════════════
def render_identified_threats():
    recs = st.session_state.user_answers
    if not recs:
        return
    st.subheader("🧾 Your threat statements")
    for r in recs:
        with st.expander(f"{r.get('matched_threat_id', 'Threat')} — {r.get('component', 'component')} / {r.get('stride', 'STRIDE')}"):
            if r.get("threat_statement"):
                st.write(r["threat_statement"])
            else:
                st.info("Statement incomplete. Complete the source, prerequisites, action, impact and assets fields when identifying the threat.")
            if r.get("statement_rationale"):
                st.caption("Evidence / assumptions: " + r["statement_rationale"])
    st.subheader(f"📋 Threats you have identified ({len(recs)}/{current_workshop['target_threats']})")
    for idx, rec in enumerate(recs):
        pred = rec["predefined_threat"]
        pts = rec.get("pts_identify", 0) if "pts_identify" in rec else _score_identify(rec, pred)[0]
        icon = "✅" if pts == 4 else "⚠️" if pts >= 2 else "❌"
        with st.expander(f"{icon} {pred['id']} · {rec['stride']} on {rec['component']}  ({pts}/4)"):
            for fb in rec.get("fb_identify", []):
                (st.success if fb.startswith("✓") else st.error)(fb)
            if rec.get("actors"):
                st.markdown("**Threat actor(s):** " + ", ".join(rec["actors"]))
            st.markdown(f"""
            <div class="stride-rule-box">
            <strong>Threat scenario:</strong> {pred['threat']}<br>
            <strong>Zone rule applied:</strong> {pred.get('stride_rule_applied', 'N/A')}<br>
            <strong>From zone:</strong> {pred.get('zone_from', 'N/A')} → <strong>To zone:</strong> {pred.get('zone_to', 'N/A')}
            </div>""", unsafe_allow_html=True)
            if pred.get("explanation"):
                st.markdown(f"""
                <div style="background:#F5F4F3;border-radius:8px;padding:12px 16px;margin:6px 0">
                <strong style="color:#274F4A">📖 Explanation</strong><br>
                <span style="font-size:0.91em;color:#423F3A">{pred['explanation']}</span></div>""", unsafe_allow_html=True)


def sync_labels_from_analysis(include_controls=False):
    ws = st.session_state.selected_workshop
    items = get_annotations(ws)
    seen = {i.get("origin") for i in items}
    added = 0
    for r in st.session_state.user_answers:
        origin = f"threat:{r['matched_threat_id']}"
        links = list(r.get("actors", []))
        if origin in seen:
            lab = next(i for i in items if i.get("origin") == origin)
            tid = lab["id"]
            lab["links"] = sorted(set(lab.get("links", [])) | set(links))
            lab["stride"] = STRIDE_LETTER_OF.get(r["stride"], lab.get("stride", ""))
        else:
            tid = _next_annotation_id(items, "threat")
            items.append({"id": tid, "kind": "threat", "label": _trunc(r["predefined_threat"].get("threat", ""), 80),
                          "target": r["component"], "links": links, "notes": "", "origin": origin,
                          "stride": STRIDE_LETTER_OF.get(r["stride"], "")})
            seen.add(origin); added += 1
        if include_controls and r.get("controlled"):
            for m in r.get("selected_mitigations", []):
                o2 = f"ctrl:{r['matched_threat_id']}:{m}"
                if o2 not in seen:
                    items.append({"id": _next_annotation_id(items, "control"), "kind": "control", "label": _trunc(m, 80),
                                  "target": r["component"], "links": [tid], "notes": "", "origin": o2})
                    seen.add(o2); added += 1
    return added


def stage_status():
    ws = st.session_state.selected_workshop
    cfg = WORKSHOPS[ws]
    sc, plan, oq = get_scope(ws), get_review_plan(ws), get_open_questions(ws)
    recs = st.session_state.user_answers
    n, tgt = len(recs), cfg["target_threats"]
    items = get_annotations(ws)
    smap = get_stride_map(ws)
    elems = element_rows(cfg)
    rated = sum(1 for r in recs if r.get("rated"))
    ctl = sum(1 for r in recs if r.get("controlled"))
    res = sum(1 for r in recs if r.get("residual"))
    mit = sum(1 for r in recs if r.get("mitre"))
    plan_ok = bool(plan["owner"].strip() and plan["full"] and plan["light"] and plan["triggers"])
    n_assets = sum(1 for i in items if i["kind"] == "asset")
    n_actors = len(get_actors(ws))
    mapped = sum(1 for r in elems if smap.get(r["key"]))
    return [
        ("scope", "Scope", "📐", scope_complete(sc),
         f"Scope statement, {len(sc['must_never'])} must-never rules, {len(sc['assumptions'])} assumptions, {len(sc['exclusions']) + len(sc['oos_components'])} exclusions"),
        ("arch", "Architecture", "🏛️", n_assets >= 2, f"{len(cfg['scenario']['components'])} components in their environments, {n_assets} assets labelled"),
        ("dfd", "DFD", "🗺️", True, f"{len(cfg['scenario']['components'])} elements and {len(cfg['scenario']['data_flows'])} data flows identified"),
        ("trust", "Trust boundaries", "🚧", boundary_checked(ws) and bool(st.session_state.get("zone_labelling_done")),
         "Boundaries drawn, crossing flows identified, zones of trust applied"),
        ("stride", "STRIDE", "⚡", n >= tgt and n_actors >= 2 and mapped >= max(1, int(0.6 * len(elems))),
         f"{n_actors} threat actors, {mapped}/{len(elems)} elements STRIDE-mapped, {n}/{tgt} threats identified"),
        ("mitre", "ATT&CK", "🎯", n > 0 and all(r.get("mitre") or (r.get("mitre_note", "").strip() and "no suitable" in r.get("mitre_note", "").lower()) for r in recs),
         f"{mit} mapped to ATT&CK; {sum(1 for r in recs if not r.get('mitre') and r.get('mitre_note', '').strip() and 'no suitable' in r.get('mitre_note', '').lower())} justified non-mappings"),
        ("scoring", "Scoring", "📊", n > 0 and rated == n, f"{rated}/{n} threats scored (impact × likelihood, 1–9)"),
        ("controls", "Controls", "🛡️", n > 0 and ctl == n, f"{ctl}/{n} threats have controls mapped"),
        ("residual", "Residual risk", "⚖️", n > 0 and res == n and len(oq["questions"]) >= 1,
         f"{res}/{n} residual risks recorded, {len(oq['questions'])} open questions"),
        ("review", "Review", "🔁", plan_ok, "Owner, review cadence and update triggers defined"),
    ]


def render_stage_review():
    ws = st.session_state.selected_workshop
    cfg = current_workshop
    s = cfg["scenario"]
    sc, oq, plan = get_scope(ws), get_open_questions(ws), get_review_plan(ws)
    recs = st.session_state.user_answers
    items = get_annotations(ws)
    smap = get_stride_map(ws)
    eid = element_ids(s)
    tabs = st.tabs([f"{ic} {lbl}" for _, lbl, ic in STAGES])
    with tabs[0]:
        st.markdown(f"**System in scope:** {sc['statement'] or '—'}")
        a, b = st.columns(2)
        a.markdown("**Must do**\n" + ("\n".join(f"- {x}" for x in sc["must_do"]) or "—"))
        b.markdown("**Must never**\n" + ("\n".join(f"- {x}" for x in sc["must_never"]) or "—"))
        if sc["assumptions"]:
            st.markdown("**Assumptions**"); st.dataframe(pd.DataFrame(sc["assumptions"]), hide_index=True, use_container_width=True)
        if sc["exclusions"] or sc["oos_components"]:
            st.markdown("**Exclusions**")
            if sc["exclusions"]:
                st.dataframe(pd.DataFrame(sc["exclusions"]), hide_index=True, use_container_width=True)
            if sc["oos_components"]:
                st.markdown("Out-of-scope components: " + ", ".join(sc["oos_components"]))
        if sc["goals"]:
            st.markdown("**Goals**\n" + "\n".join(f"- {x}" for x in sc["goals"]))
    with tabs[1]:
        paths = component_boundaries(cfg)
        st.dataframe(pd.DataFrame([{"Component": c["name"], "Type": KIND_LABEL[c["type"]], "Runs in": " › ".join(paths.get(c["name"], [])),
                                    "Description": c["description"]} for c in s["components"]]), use_container_width=True, hide_index=True)
        assets = [i for i in items if i["kind"] == "asset"]
        if assets:
            st.markdown("**Assets:** " + "; ".join(f"{i['id']} {i['label']} (on {i['target']})" for i in assets))
    with tabs[2]:
        st.dataframe(pd.DataFrame([{"ID": eid[c["name"]], "Element": c["name"], "Kind": KIND_LABEL[c["type"]], "Zone": c.get("zone", "N/A"),
                                    "Score (0-9)": c.get("zone_score", "?")} for c in s["components"]]), use_container_width=True, hide_index=True)
        st.dataframe(pd.DataFrame([{"ID": eid[_flow_key(f)], "Flow": _flow_key(f), "Data": f["data"], "Protocol": f["protocol"]}
                                   for f in s["data_flows"]]), use_container_width=True, hide_index=True)
    with tabs[3]:
        cross = flow_crossings(cfg)
        st.dataframe(pd.DataFrame([{"ID": eid[k], "Flow": k, "Boundaries crossed": ", ".join(v) or "—"} for k, v in cross.items()]),
                     use_container_width=True, hide_index=True)
    with tabs[4]:
        actors = get_actors(ws)
        if actors:
            st.markdown("**Threat actors**")
            st.dataframe(pd.DataFrame([{"ID": a["id"], "Actor": a["label"], "Capability": a.get("capability", ""),
                                        "Entry points": ", ".join(_actor_targets(a))} for a in actors]), hide_index=True, use_container_width=True)
        if smap:
            st.markdown("**STRIDE mapping per element**")
            st.dataframe(pd.DataFrame([{"ID": eid.get(k, ""), "Element": k, "STRIDE": " ".join(v)} for k, v in smap.items()]),
                         hide_index=True, use_container_width=True)
        for a in recs:
            pred = a.get("predefined_threat", {})
            pts = a.get("pts_identify", 0)
            css = "correct-answer" if pts == 4 else "partial-answer" if pts >= 2 else "incorrect-answer"
            st.markdown(f"""<div class="{css}"><strong>{a['matched_threat_id']}</strong>: {pred.get('threat', '')}<br>
            Your answer: {a['stride']} on {_esc(a['component'])} · Zone rule: {pred.get('stride_rule_applied', 'N/A')}</div>""", unsafe_allow_html=True)
    with tabs[5]:
        mp = [r for r in recs if r.get("mitre")]
        if mp:
            st.markdown(attack_matrix_html(mp), unsafe_allow_html=True)
            st.dataframe(pd.DataFrame([{"Threat": r["matched_threat_id"], "STRIDE": r["stride"],
                                        "Techniques": ", ".join(f"{t} {ATTACK_BY_ID[t]['name']}" for t in r["mitre"] if t in ATTACK_BY_ID),
                                        "Attack path": r.get("mitre_note", "")} for r in mp]), hide_index=True, use_container_width=True)
        else:
            st.info("No threats were mapped to ATT&CK.")
    with tabs[6]:
        rated = [r for r in recs if r.get("rated")]
        if rated:
            st.markdown(risk_matrix_html([(r["likelihood_n"], r["impact_n"], r["matched_threat_id"]) for r in rated]), unsafe_allow_html=True)
            st.dataframe(pd.DataFrame([{"Threat": r["matched_threat_id"], "Likelihood": r["likelihood"], "Impact": r["impact"],
                                        "Risk": rec_risk(r), "Band": risk_band(rec_risk(r))}
                                       for r in sorted(rated, key=lambda r: -rec_risk(r))]), hide_index=True, use_container_width=True)
        else:
            st.info("No threats were scored.")
    with tabs[7]:
        for a in recs:
            if not a.get("controlled"):
                continue
            correct = set(a["predefined_threat"]["correct_mitigations"])
            st.markdown(f"**{a['matched_threat_id']}** — {_control_chips(a['selected_mitigations'])}", unsafe_allow_html=True)
            for m in a["selected_mitigations"]:
                st.markdown(f"- {'✅' if m in correct else '❌'} {control_category(m)}: {m}")
        for stride_cat, owasp_info in OWASP_STRIDE_MAP.items():
            used = any(a["stride"] == stride_cat for a in recs)
            st.markdown(f"""<div class="owasp-box">{'✅' if used else '⭕'} <strong>{stride_cat}</strong> → {', '.join(owasp_info['owasp'])}<br>
            Key controls: {'; '.join(owasp_info['controls'][:2])}</div>""", unsafe_allow_html=True)
    with tabs[8]:
        res = [r for r in recs if r.get("residual")]
        if res:
            st.dataframe(pd.DataFrame([{"Threat": r["matched_threat_id"], "Inherent": rec_risk(r), "Residual": rec_residual(r),
                                        "Decision": r["residual"]["decision"], "Rationale": r["residual"]["rationale"]} for r in res]),
                         hide_index=True, use_container_width=True)
        if oq["questions"]:
            st.markdown("**Open questions**\n" + "\n".join(f"- {q}" for q in oq["questions"]))
        if oq["accepted"]:
            st.markdown(f"**Accepted-risk statement:** {oq['accepted']}")
    with tabs[9]:
        st.markdown(f"**Owner:** {plan['owner'] or '—'}  ·  **Security's role:** {plan['security_role'] or '—'}  ·  **Next lightweight review:** {plan['next_review'] or '—'}")
        for title, key in (("Full-workshop triggers", "full"), ("Lightweight review checks", "light"), ("Update triggers", "triggers")):
            if plan[key]:
                st.markdown(f"**{title}**\n" + "\n".join(f"- {x}" for x in plan[key]))
        if plan["notes"]:
            st.markdown(f"**Keeping it alive:** {plan['notes']}")


def build_pdf_extra():
    ws = st.session_state.selected_workshop
    return {"scope": get_scope(ws), "open_questions": get_open_questions(ws), "review_plan": get_review_plan(ws),
            "labels": list(get_annotations(ws)), "stride_map": dict(get_stride_map(ws))}



# ═══════════════════════════════════════════════════════════════════════════════
#  SIDEBAR
# ═══════════════════════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown("""
    <div class="brand">
      <div class="logo">🔒</div>
      <div class="name">Threat Modeling Lab</div>
      <div class="tag">Scope → Architecture → DFD → Trust boundaries → STRIDE → ATT&amp;CK → Scoring → Controls → Residual → Review</div>
    </div>
    """, unsafe_allow_html=True)
    st.markdown("---")
    st.markdown("**🗺️ The 10 Stages**")
    st.markdown("""
    1. 📐 **Scope** – goals, assumptions, exclusions
    2. 🏛️ **Architecture** – what runs where, assets
    3. 🗺️ **DFD** – elements and data flows
    4. 🚧 **Trust boundaries** – crossings, zones
    5. ⚡ **STRIDE** – threat actors, per-element mapping
    6. 🎯 **ATT&CK** – techniques and tactics
    7. 📊 **Scoring** – impact × likelihood
    8. 🛡️ **Controls** – OWASP-mapped
    9. ⚖️ **Residual risk** – what remains
    10. 🔁 **Review** – owners and triggers
    """)
    st.markdown("---")

    if st.session_state.selected_workshop:
        ws_name = WORKSHOPS.get(st.session_state.selected_workshop,{}).get("name","")
        step_names = {p: v[0] for p, v in PAGES.items()}
        cur_step_name = step_names.get(st.session_state.current_step,"")
        ws_level = WORKSHOPS.get(st.session_state.selected_workshop,{}).get("level","")
        st.markdown(f"""
        <div class="now-card">
          <div class="now-eyebrow">Now studying</div>
          <div class="now-title">{ws_name}</div>
          <div class="now-meta">{ws_level} · {cur_step_name}</div>
        </div>
        """, unsafe_allow_html=True)

        if st.session_state.max_score > 0:
            pct = st.session_state.total_score / st.session_state.max_score * 100
            bar_color = "#4A994D" if pct >= 80 else "#E9A435" if pct >= 60 else "#D84642"
            st.markdown(f"""
            <div class="score-line">
            Score: <strong>{st.session_state.total_score}/{st.session_state.max_score}</strong>
            &nbsp;({pct:.0f}%)
            </div>""", unsafe_allow_html=True)
            st.progress(pct / 100)
        st.markdown("---")

    st.markdown("### Select Workshop")
    for ws_id, ws_config in WORKSHOPS.items():
        unlocked = is_workshop_unlocked(ws_id)
        completed = ws_id in st.session_state.completed_workshops
        col1, col2 = st.columns([3, 1])
        with col1:
            if st.button(f"Workshop {ws_id}", key=f"ws_{ws_id}",
                         disabled=not unlocked, use_container_width=True):
                start_workshop(ws_id)
                save_progress()
                st.rerun()
        with col2:
            if completed:
                st.markdown('<span class="badge-completed">✓</span>', unsafe_allow_html=True)
            elif not unlocked:
                st.markdown('<span class="badge-locked">🔒</span>', unsafe_allow_html=True)

        if not unlocked and ws_id != "1":
            uk = f"unlock_{ws_id}"
            if uk not in st.session_state.show_unlock_form:
                st.session_state.show_unlock_form[uk] = False
            if st.button(f"🔓 Unlock", key=f"unlock_btn_{ws_id}", use_container_width=True):
                st.session_state.show_unlock_form[uk] = not st.session_state.show_unlock_form[uk]
                st.rerun()
            if st.session_state.show_unlock_form[uk]:
                with st.form(f"unlock_form_{ws_id}"):
                    st.caption("Enter the unlock code provided by your instructor")
                    code = st.text_input("Unlock Code", type="password", key=f"code_{ws_id}")
                    if st.form_submit_button("Submit"):
                        if verify_unlock_code(ws_id, code):
                            st.session_state.unlocked_workshops.add(ws_id)
                            st.session_state.show_unlock_form[uk] = False
                            save_progress()
                            st.success("✅ Unlocked!")
                            st.rerun()
                        else:
                            st.error("❌ Invalid code")

        # Only show detail expander for selected workshop to avoid rendering all
        if st.session_state.selected_workshop == ws_id:
            with st.expander("ℹ️ Details", expanded=False):
                st.caption(f"**Level:** {ws_config['level']}")
                st.caption(f"**Duration:** {ws_config['duration']}")
                st.caption(f"**Threats:** {ws_config['target_threats']}")

    st.markdown("---")
    with st.expander("⚡ STRIDE Quick Reference"):
        stride_items = [
            ("S","Spoofing","#FBD1D5","Identity impersonation — pretending to be someone else","Zone-0 reachable nodes"),
            ("T","Tampering","#F9DFB8","Data modification — altering data or code","Less→more critical flows"),
            ("R","Repudiation","#FBF5C8","Denying actions — no proof of who did what","Nodes with Spoofing+Tampering"),
            ("I","Info Disclosure","#E5F5F3","Data exposure — secrets reaching wrong party","More→less critical flows"),
            ("D","DoS","#F1E8F2","Availability — crashing or degrading services","Zone-0→any node flows"),
            ("E","EoP","#EFEFEE","Privilege escalation — gaining unauthorized access","Higher nodes adj to lower"),
        ]
        for letter, name, bg, desc, rule in stride_items:
            st.markdown(f"""
            <div style="background:{bg};border-radius:6px;padding:8px 10px;margin:3px 0;font-size:0.82em">
              <strong style="font-size:1em">{letter} — {name}</strong><br>
              <span style="color:#444">{desc}</span><br>
              <span style="color:#777;font-size:0.85em">Rule: {rule}</span>
            </div>
            """, unsafe_allow_html=True)

    with st.expander("🏷️ Zone Scale (0–9)"):
        zone_mini = [
            (0,"Not in Control","#EFEEED","#7F786B"),
            (1,"Minimal Trust","#CAE4CB","#3E8842"),
            (3,"Standard App","#FBF5C8","#E9A435"),
            (5,"Elevated Trust","#F9DFB8","#D55611"),
            (7,"Critical","#FBD1D5","#BA3434"),
            (9,"Maximum Security","#F7AF99","#B23D19"),
        ]
        for score, label, bg, border in zone_mini:
            st.markdown(f"""
            <div style="background:{bg};border-left:3px solid {border};border-radius:4px;
                        padding:5px 8px;margin:2px 0;font-size:0.8em">
              <strong>z{score}</strong> — {label}
            </div>
            """, unsafe_allow_html=True)

    with st.expander("📐 Zone-Direction Rules"):
        rules = [
            ("↑ Tampering","Less → More critical zone flow"),
            ("↓ Info Disclosure","More → Less critical zone flow"),
            ("💥 DoS","Zone-0 → any node"),
            ("🎭 Spoofing","Node reachable from Zone-0"),
            ("🔄 Repudiation","Node where Spoofing + Tampering both apply"),
            ("⬆ EoP","Higher-zone node adjacent to lower-zone node"),
        ]
        for rule, desc in rules:
            st.markdown(f"**{rule}**: {desc}")


# ═══════════════════════════════════════════════════════════════════════════════
#  HOME PAGE
# ═══════════════════════════════════════════════════════════════════════════════
if not st.session_state.selected_workshop:
    # ── Hero banner ─────────────────────────────────────────────────────────
    st.markdown("""
    <div class="hero">
      <div class="eyebrow">Threat modeling lab</div>
      <h1>STRIDE Threat Modeling Mastery Lab</h1>
      <p>From security novice to professional threat modeler in four progressive workshops, following a ten-stage process from scope to review.</p>
      <div class="chips">
        <span class="chip">4 hands-on workshops</span>
        <span class="chip">30 real-world threats</span>
        <span class="chip">Live architecture diagrams</span>
        <span class="chip">MITRE ATT&amp;CK mapping</span>
        <span class="chip">OWASP Top 10 aligned</span>
      </div>
    </div>
    """, unsafe_allow_html=True)

    # ── Overall progress (if returning student) ──────────────────────────────
    completed_count = len(st.session_state.completed_workshops)
    if completed_count > 0:
        total_ws = 4
        prog_pct = completed_count / total_ws
        st.markdown(f"""
        <div class="success-box">
        <strong>🎓 Your Progress: {completed_count}/{total_ws} workshops completed</strong>
        </div>
        """, unsafe_allow_html=True)
        st.progress(prog_pct)
        st.markdown("---")

    # ── Learning journey tabs ──────────────────────────────────────────────
    home_tabs = st.tabs(["🗺️ Learning Path", "🧠 What You'll Master", "📋 The 10-Stage Process", "🏆 Skill Tree"])

    with home_tabs[0]:
        st.markdown("### Your Journey from Novice to Expert")
        st.markdown("""
        <div class="info-box">
        This lab uses the <strong>Infosec Institute 4-Step Methodology</strong> — the same framework used
        by Microsoft, OWASP, and enterprise security teams. Each workshop adds a new layer of complexity,
        building on what you've learned before.<br><br>
        Every workshop follows the same <strong>10 stages</strong>: Scope → Architecture → DFD → Trust boundaries → STRIDE → ATT&amp;CK → Scoring → Controls → Residual risk → Review.
        </div>
        """, unsafe_allow_html=True)

        ws_data = list(WORKSHOPS.items())
        level_colors = {"Foundation":"#368D82","Intermediate":"#347737","Advanced":"#D55611","Expert":"#703988"}
        level_icons  = {"Foundation":"🌱","Intermediate":"🌿","Advanced":"🌳","Expert":"🔥"}
        for idx, (ws_id, ws) in enumerate(ws_data):
            unlocked  = is_workshop_unlocked(ws_id)
            completed = ws_id in st.session_state.completed_workshops
            lc = level_colors.get(ws["level"], "#226259")
            li = level_icons.get(ws["level"], "📚")
            status_html = (
                '<span class="badge-completed">✅ Completed</span>' if completed else
                '<span class="badge-available">🔓 Available</span>' if unlocked else
                '<span class="badge-locked">🔒 Locked</span>'
            )
            connector = f'<div style="text-align:center;color:{lc};font-size:1.5em;margin:-4px 0">↓</div>' if idx < len(ws_data)-1 else ""
            st.markdown(f"""
            <div class="premium-card" style="border-left:5px solid {lc}">
              <div style="display:flex;justify-content:space-between;align-items:flex-start">
                <div style="flex:1">
                  <h4 style="margin:0 0 4px 0;color:{lc}">{li} Workshop {ws_id}: {ws['scenario']['title']}</h4>
                  <p style="margin:0 0 8px 0;color:#555;font-size:0.9em">{ws['scenario']['description']} · {ws['scenario']['business_context']}</p>
                  <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px">
                    <span style="background:#F5F4F3;padding:3px 10px;border-radius:12px;font-size:0.8em;color:#555">📊 {ws['level']}</span>
                    <span style="background:#F5F4F3;padding:3px 10px;border-radius:12px;font-size:0.8em;color:#555">⏱️ {ws['duration']}</span>
                    <span style="background:#F5F4F3;padding:3px 10px;border-radius:12px;font-size:0.8em;color:#555">🎯 {ws['target_threats']} threats</span>
                    <span style="background:#F5F4F3;padding:3px 10px;border-radius:12px;font-size:0.8em;color:#555">🏗️ {ws.get('architecture_type','')}</span>
                  </div>
                  <div><strong style="font-size:0.85em;color:#555">You will learn:</strong><br>
                  {''.join(f"<span style='font-size:0.82em;color:#444'>• {lo}</span><br>" for lo in ws.get('learning_objectives',[]))}
                  </div>
                </div>
                <div style="text-align:right;padding-left:16px">{status_html}</div>
              </div>
            </div>
            {connector}
            """, unsafe_allow_html=True)

            if unlocked and not completed:
                if st.button(f"▶ Start Workshop {ws_id}: {ws['scenario']['title']}", key=f"start_home_{ws_id}", type="primary"):
                    st.session_state.selected_workshop = ws_id
                    st.session_state.current_step = 1
                    save_progress()
                    st.rerun()
            elif completed:
                if st.button(f"↩ Revisit Workshop {ws_id}", key=f"revisit_home_{ws_id}"):
                    st.session_state.selected_workshop = ws_id
                    st.session_state.current_step = 1
                    save_progress()
                    st.rerun()

    with home_tabs[1]:
        st.markdown("### What You Will Master by Completing All 4 Workshops")
        skills = [
            ("🏗️", "System Architecture Analysis",
             "Read any system diagram and immediately identify Interactors (external entities), Modules (processes + data stores), and Connections (data flows). Classify every component using DFD notation.",
             ["Web apps","Microservices","SaaS platforms","IoT systems"]),
            ("🏷️", "Criticality Zone Assignment",
             "Assign a numerical Zone of Trust score (0–9) to every component in a system. Understand why Zone 0 = untrusted external, Zone 9 = life-critical internal, and everything in between.",
             ["Zone labelling","Score calibration","Trust boundary identification","Zone rationale"]),
            ("⚡", "Zone-Based Threat Discovery",
             "Apply the 5 zone-direction rules to mechanically discover which STRIDE categories apply to each data flow and node. No guesswork — pure systematic derivation.",
             ["Tampering: less→more critical","Info Disclosure: more→less critical","DoS: Zone-0→any","Spoofing: Zone-0 reachable","EoP: higher zone adjacent to lower"]),
            ("🛡️", "OWASP Control Mapping",
             "Map every STRIDE threat to the OWASP Top 10 (2021) and identify the specific controls that mitigate it. Understand which controls address which STRIDE categories and why.",
             ["OWASP A01–A10 mapping","Control selection","Defence-in-depth","Compliance alignment"]),
            ("📊", "Attack Tree Construction",
             "Build and read attack trees showing all paths to a threat goal. Understand AND/OR node logic — how attackers chain simple steps into sophisticated attacks.",
             ["Goal decomposition","AND-node chaining","OR-node enumeration","Attack path prioritisation"]),
            ("🏥", "Domain-Specific Threat Modeling",
             "Apply STRIDE to four distinct architecture types: traditional web apps, microservices, multi-tenant SaaS, and IoT/healthcare systems — each with domain-specific threats and compliance frameworks.",
             ["PCI-DSS for e-commerce","SOC 2 for SaaS","HIPAA for healthcare","FDA requirements for IoT"]),
        ]
        for icon, title, desc, topics in skills:
            with st.expander(f"{icon} {title}", expanded=False):
                st.markdown(f"""
                <div class="learning-box">{desc}</div>
                """, unsafe_allow_html=True)
                st.markdown("**Topics covered:**")
                cols_sk = st.columns(2)
                for i, t in enumerate(topics):
                    cols_sk[i%2].markdown(f"✓ {t}")

    with home_tabs[2]:
        st.markdown("### The 10 stages you follow in every workshop")
        st.markdown("""
| Stage | What you produce | Where the Infosec 4-step method fits |
|---|---|---|
| 1. 📐 **Scope** | System in scope, must-do / must-never rules, assumptions, exclusions, measurable goals | — (added up front) |
| 2. 🏛️ **Architecture** | The system as built: components, environments, labelled assets | — (added) |
| 3. 🗺️ **DFD** | Data-flow diagram with elements (E, P, D) and flows (F) | Step 1 *Design* |
| 4. 🚧 **Trust boundaries** | Boundaries, boundary-crossing flows, zones of trust (0–9) | Step 2 *Zones of Trust* |
| 5. ⚡ **STRIDE** | Threat actors and entry points, STRIDE mapped to every element, threats derived with the zone rules | Step 3 *Discover threats* |
| 6. 🎯 **ATT&CK** | Each threat mapped to MITRE ATT&CK techniques and tactics | — (added) |
| 7. 📊 **Scoring** | Impact × likelihood on a 1–3 scale → risk score 1–9 | — (added) |
| 8. 🛡️ **Controls** | Guardrails, filtering, access rules and monitoring, mapped to OWASP | Step 4 *Mitigations* |
| 9. ⚖️ **Residual risk** | Risk after controls, decisions, open questions | — (added) |
| 10. 🔁 **Review** | Owner, review cadence, full-workshop and update triggers | — (added) |
""")
        st.markdown("### The Infosec 4-step method in detail")
        steps_detail = [
            ("1", "Design the Threat Model", "#F1F0EF", "#35A091",
             "Create a Data Flow Diagram (DFD) that captures the complete system architecture.",
             ["Identify all <strong>Interactors</strong> — external people and systems you don't control",
              "Map all <strong>Modules</strong> — processes that transform data + data stores that persist it",
              "Draw all <strong>Connections</strong> — every data flow, its protocol, and what data it carries",
              "Document <strong>Trust Boundaries</strong> — the lines where control or ownership changes"],
             "Before you can find threats you must know exactly what you're protecting. A missing component in the diagram means a missed threat.",
             "Microsoft Threat Modeling Tool, STRIDE-per-Element, DFD Level 0/1/2"),
            ("2", "Apply Zones of Trust", "#FBF5C8", "#E48028",
             "Assign every component a criticality level from 0 (untrusted) to 9 (life-critical).",
             ["Zone 0: Not in system control (external users, 3rd party services)",
              "Zone 1–2: Entry points — minimal authentication enforced",
              "Zone 3–4: Application layer — standard security controls",
              "Zone 5–6: Elevated trust — privileged services, payment processing",
              "Zone 7–8: Critical — databases, regulated data stores",
              "Zone 9: Maximum security — safety-critical, life-critical systems"],
             "Zones turn threat discovery from art into science. The zone difference between source and destination tells you which STRIDE categories mechanically apply.",
             "Microsoft SDL Zone of Trust, NIST 800-207 Zero Trust"),
            ("3", "Discover Threats with STRIDE", "#F9DFB8", "#D55611",
             "Apply zone-direction rules to systematically derive applicable STRIDE threats.",
             ["<strong>Flows:</strong> Tampering on less→more critical flows; Info Disclosure on more→less",
              "<strong>Flows from Zone 0:</strong> Always check Denial of Service",
              "<strong>Nodes reachable from Zone 0:</strong> Spoofing applies",
              "<strong>Nodes where Spoofing + Tampering both apply:</strong> Repudiation applies",
              "<strong>Higher-zone nodes adjacent to lower-zone nodes:</strong> Elevation of Privilege"],
             "These rules come from Microsoft's original STRIDE paper. They make threat discovery repeatable — two analysts working independently produce the same threat list.",
             "STRIDE-per-Element, SAFECode Threat Modeling, OWASP Threat Dragon"),
            ("4", "Explore Mitigations and Controls", "#EFEFEE", "#347737",
             "Map each identified STRIDE threat to OWASP Top 10 and select specific controls.",
             ["Spoofing → OWASP A07 (Authentication Failures) → MFA, secure sessions",
              "Tampering → OWASP A03 (Injection) + A08 (Integrity) → parameterised queries, HMAC",
              "Repudiation → OWASP A09 (Logging Failures) → immutable audit logs, SIEM",
              "Info Disclosure → OWASP A02 (Crypto Failures) → TLS 1.3, AES-256 at rest",
              "DoS → OWASP A04 (Insecure Design) → rate limiting, circuit breakers, WAF",
              "EoP → OWASP A01 (Broken Access Control) → RBAC, deny-by-default"],
             "Controls must be specific, implementable, and auditable. Vague controls like 'add security' are useless — each must map to a concrete engineering action.",
             "OWASP Top 10 (2021), OWASP ASVS v4, NIST 800-53, CIS Controls v8"),
        ]
        for num, title, bg, border, summary, bullets, insight, refs in steps_detail:
            st.markdown(f"""
            <div class="premium-card" style="border-left:5px solid {border};background:{bg}20">
              <h3 style="color:{border};margin:0 0 8px 0">Step {num}: {title}</h3>
              <p style="margin:0 0 10px 0;color:#333">{summary}</p>
              <div style="margin-bottom:10px">
                {''.join(f"<div style='font-size:0.88em;color:#444;padding:3px 0'>▸ {b}</div>" for b in bullets)}
              </div>
              <div class="callout-box" style="margin:8px 0">
                <strong>💡 Why this step matters:</strong> {insight}
              </div>
              <div style="font-size:0.8em;color:#777;margin-top:6px">📖 Industry references: {refs}</div>
            </div>
            """, unsafe_allow_html=True)

    with home_tabs[3]:
        st.markdown("### 🏆 Skill Progression Tree")
        st.markdown("""
        <div class="info-box">
        Each workshop unlocks new skills. Skills build on each other — you cannot skip ahead
        without the foundational knowledge. Track your progress through the tree below.
        </div>
        """, unsafe_allow_html=True)

        completed_ws = st.session_state.completed_workshops
        skill_tree = [
            ("WS1", "Foundation",
             ["DFD element classification","Zone 0–7 assignment","Basic STRIDE rules","OWASP A01–A10 mapping","XSS / SQLi / IDOR recognition"],
             "1" in completed_ws),
            ("WS2", "Intermediate",
             ["Service mesh threat modeling","mTLS & BOLA identification","Distributed tracing for Repudiation","OWASP API Security Top 10","Microservices zone rules"],
             "2" in completed_ws),
            ("WS3", "Advanced",
             ["Multi-tenant isolation threats","Row-Level Security design","Cross-tenant EoP patterns","SOC 2 compliance mapping","Kafka/streaming threat surfaces"],
             "3" in completed_ws),
            ("WS4", "Expert",
             ["IoT/edge trust boundary analysis","Replay attack detection design","HIPAA/FDA control mapping","Life-critical zone 9 threats","HL7/legacy protocol security"],
             "4" in completed_ws),
        ]
        level_grad = {
            "Foundation":  "#368D82",
            "Intermediate":"#205924",
            "Advanced":    "#D55611",
            "Expert":      "#4C2C74",
        }
        cols_tree = st.columns(4)
        for col, (ws_label, level, skills_list, done) in zip(cols_tree, skill_tree):
            with col:
                grad = level_grad.get(level,"#226259")
                alpha = "1" if done else "0.45"
                skill_rows = "".join(
                    f'<div style="font-size:0.8em;padding:3px 0;color:#{"E8F4FD" if done else "777"}">{"✅" if done else "⭕"} {s}</div>'
                    for s in skills_list
                )
                st.markdown(f"""
                <div style="background:{grad};border-radius:10px;padding:16px;opacity:{alpha};
                            box-shadow:0 3px 10px rgba(0,0,0,0.2);min-height:200px">
                  <div style="color:white;font-weight:700;font-size:1em;margin-bottom:4px">{ws_label}</div>
                  <div style="color:rgba(255,255,255,0.7);font-size:0.8em;margin-bottom:10px">{level}</div>
                  {skill_rows}
                  {'<div style="margin-top:10px;background:rgba(255,255,255,0.2);border-radius:6px;padding:4px 8px;text-align:center;color:white;font-size:0.8em;font-weight:600">✅ MASTERED</div>' if done else ''}
                </div>
                """, unsafe_allow_html=True)

    st.markdown("---")
    # Quick-start CTA
    st.markdown("""
    <div class="key-concept">
      <h4>Ready to Begin?</h4>
      <p style="margin:0;font-size:1em">Start with Workshop 1 — no prior security knowledge needed. Each step teaches
      you the <em>why</em> behind every decision, not just the what. By Workshop 4 you will be
      threat modeling systems that protect human lives.</p>
    </div>
    """, unsafe_allow_html=True)

    ws1_config = WORKSHOPS["1"]
    if st.button("▶ Start Workshop 1: TechMart E-Commerce →", type="primary", use_container_width=True):
        st.session_state.selected_workshop = "1"
        st.session_state.current_step = 1
        save_progress()
        st.rerun()
    st.stop()


# ═══════════════════════════════════════════════════════════════════════════════
#  WORKSHOP SELECTED – STEP NAVIGATION
# ═══════════════════════════════════════════════════════════════════════════════
current_workshop = WORKSHOPS[st.session_state.selected_workshop]
workshop_threats = PREDEFINED_THREATS.get(st.session_state.selected_workshop, [])

# Premium workshop header
ws_level_color = {"Foundation":"#368D82","Intermediate":"#347737","Advanced":"#D55611","Expert":"#703988"}.get(current_workshop["level"],"#226259")
st.markdown(f"""
<div style="display:flex;align-items:center;gap:16px;margin-bottom:4px">
  <div>
    <h1 style="margin:0;color:#226259">{current_workshop['name']}</h1>
    <div style="display:flex;gap:8px;margin-top:6px;flex-wrap:wrap">
      <span style="background:{ws_level_color};color:white;padding:3px 12px;border-radius:12px;font-size:0.82em;font-weight:600">{current_workshop['level']}</span>
      <span style="background:#F5F4F3;color:#555;padding:3px 12px;border-radius:12px;font-size:0.82em">⏱️ {current_workshop['duration']}</span>
      <span style="background:#F5F4F3;color:#555;padding:3px 12px;border-radius:12px;font-size:0.82em">🎯 {current_workshop['target_threats']} threats</span>
      <span style="background:#F5F4F3;color:#555;padding:3px 12px;border-radius:12px;font-size:0.82em">🏗️ {current_workshop.get('architecture_type','')}</span>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

# ── Stage tracker: Scope → DFD → STRIDE → Scoring → Controls → Residual risk → Review ──
_page = int(st.session_state.current_step)
_page_name, _stage_id = PAGES.get(_page, ("", "scope"))
_stage_idx = STAGE_IDS.index(_stage_id)
_parts = []
for _i, (_sid, _label, _icon) in enumerate(STAGES):
    _state = "done" if _i < _stage_idx else ("active" if _i == _stage_idx else "todo")
    _dot = "✓" if _state == "done" else (_icon if _state == "active" else str(_i + 1))
    _parts.append(f'<div class="stg stg-{_state}"><div class="stg-dot">{_dot}</div><div class="stg-label">{_label}</div></div>')
_sep = '<div class="stg-line"></div>'
st.markdown('<div class="stepper">' + _sep.join(_parts) + '</div>', unsafe_allow_html=True)
st.caption(f"Stage {_stage_idx + 1} of {len(STAGES)} · **{STAGES[_stage_idx][1]}** — {_page_name}")
st.progress(((PAGE_ORDER.index(_page) + 1) / len(PAGE_ORDER)) if _page in PAGE_ORDER else 0.05)
st.markdown("---")


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 1 · STAGE 1 SCOPE (NEW)
# ─────────────────────────────────────────────────────────────────────────────
if st.session_state.current_step == 1:
    render_scope_page()


# ─────────────────────────────────────────────────────────────────────────────
# PAGES 14-18 · ARCHITECTURE, TRUST BOUNDARIES, THREAT ACTORS, STRIDE MAPPING, ATT&CK
# ─────────────────────────────────────────────────────────────────────────────
elif st.session_state.current_step == 14:
    render_architecture_page()

elif st.session_state.current_step == 15:
    render_trust_boundary_page()

elif st.session_state.current_step == 16:
    render_threat_actors_page()

elif st.session_state.current_step == 17:
    render_stride_mapping_page()

elif st.session_state.current_step == 18:
    render_mitre_page()


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 2 · STAGE 3 DFD — DATA-FLOW DIAGRAM
# ─────────────────────────────────────────────────────────────────────────────
elif st.session_state.current_step == 2:
    st.header("Step 3: Draw the Data-Flow Diagram (DFD)")
    scope_reminder()

    st.markdown("""
    <div class="methodology-step">
    <strong>🗺️ Stage 3 · DFD (Infosec Step 1: Design)</strong><br>
    The first step is to create a Data Flow Diagram (DFD) that identifies all 
    <strong>Interactors</strong> (external entities), <strong>Modules</strong> (processes and data stores), 
    and <strong>Connections</strong> (data flows between them).<br><br>
    This visual representation is the foundation on which all subsequent threat analysis is built.
    </div>
    """, unsafe_allow_html=True)

    scenario = current_workshop["scenario"]

    col1, col2 = st.columns([2, 1])
    with col1:
        st.subheader("📋 System Overview")
        st.markdown(f"**System:** {scenario['description']}")
        st.markdown(f"**Business Context:** {scenario['business_context']}")

        st.markdown("### 🎯 Security Objectives (CIA)")
        for obj in scenario["objectives"]:
            st.markdown(f"- {obj}")

        st.markdown("### 💎 Critical Assets to Protect")
        for asset in scenario["assets"]:
            st.markdown(f"- {asset}")

        st.markdown("### 📜 Regulatory Compliance")
        for comp in scenario["compliance"]:
            st.markdown(f"- {comp}")

    with col2:
        st.markdown(f"""
        <div class="success-box">
        <strong>Workshop Objectives</strong><br><br>
        📊 Identify {current_workshop['target_threats']} threats<br>
        ⏱️ {current_workshop['duration']}<br>
        📈 {current_workshop['level']} level<br>
        🎯 Score 90%+ for mastery!<br><br>
        <strong>Learning Objectives:</strong>
        </div>
        """, unsafe_allow_html=True)
        for lo in current_workshop.get("learning_objectives", [])[:3]:
            st.markdown(f"• {lo}")

    st.markdown("---")

    # DFD ELEMENT TYPES – educational content
    st.subheader("📘 The 3 Types of DFD Elements")

    st.markdown("""
    <div class="info-box">
    Every threat model diagram uses exactly these three types of elements 
    (per the Infosec methodology). Learning to classify them correctly is essential — 
    because <strong>different element types are vulnerable to different STRIDE categories</strong>.
    </div>
    """, unsafe_allow_html=True)

    col_a, col_b, col_c = st.columns(3)
    with col_a:
        st.markdown("""
        <div style="background:white;border-radius:10px;padding:18px;border:2px solid #FBD1D5;
                    box-shadow:0 2px 8px rgba(0,0,0,0.07);height:100%">
        <div style="font-size:1.3em;margin-bottom:6px">👤</div>
        <h4 style="margin:0 0 8px 0;color:#BA3434;font-family:Inter,Arial">Interactors</h4>
        <div style="font-size:0.82em;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:#E35E5C;margin-bottom:8px">External Entities</div>
        <p style="font-size:0.88em;color:#444;margin:0 0 10px 0">People and systems <strong>outside your control</strong> that send data to or receive data from your system.</p>
        <div style="background:#FDECEF;border-radius:6px;padding:8px 10px;margin:6px 0;font-size:0.82em">
          <strong>Always Zone 0</strong> — Not in Control of System<br>
          <span style="color:#666">Examples: End users, payment gateways, IoT sensors, partner APIs</span>
        </div>
        <div style="font-size:0.82em;color:#555;margin-top:8px">
          <strong>STRIDE exposure:</strong><br>
          ⚫ Spoofing (they can impersonate others)<br>
          ⚫ DoS (they can flood your entry points)<br>
          <em style="color:#888">Cannot be Tampering or EoP — they have no internal access</em>
        </div>
        </div>
        """, unsafe_allow_html=True)
    with col_b:
        st.markdown("""
        <div style="background:white;border-radius:10px;padding:18px;border:2px solid #C7EFEA;
                    box-shadow:0 2px 8px rgba(0,0,0,0.07);height:100%">
        <div style="font-size:1.3em;margin-bottom:6px">⚙️</div>
        <h4 style="margin:0 0 8px 0;color:#35A091;font-family:Inter,Arial">Modules</h4>
        <div style="font-size:0.82em;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:#3CAFA0;margin-bottom:8px">Processes & Data Stores</div>
        <p style="font-size:0.88em;color:#444;margin:0 0 10px 0">Components <strong>inside your system</strong> — processes transform data, data stores persist it.</p>
        <div style="background:#F1F0EF;border-radius:6px;padding:8px 10px;margin:6px 0;font-size:0.82em">
          <strong>Zones 1–9</strong> — assigned based on criticality<br>
          <span style="color:#666">Examples: APIs, databases, auth services, message queues</span>
        </div>
        <div style="font-size:0.82em;color:#555;margin-top:8px">
          <strong>STRIDE exposure:</strong><br>
          ⚫ All 6 STRIDE categories can apply<br>
          <em style="color:#888">Highest-complexity threat surface — the zone determines which rules apply</em>
        </div>
        </div>
        """, unsafe_allow_html=True)
    with col_c:
        st.markdown("""
        <div style="background:white;border-radius:10px;padding:18px;border:2px solid #CAE4CB;
                    box-shadow:0 2px 8px rgba(0,0,0,0.07);height:100%">
        <div style="font-size:1.3em;margin-bottom:6px">🔗</div>
        <h4 style="margin:0 0 8px 0;color:#347737;font-family:Inter,Arial">Connections</h4>
        <div style="font-size:0.82em;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:#3E8842;margin-bottom:8px">Data Flows</div>
        <p style="font-size:0.88em;color:#444;margin:0 0 10px 0">Every path <strong>data travels</strong> between components — the network of information exchange.</p>
        <div style="background:#EFEFEE;border-radius:6px;padding:8px 10px;margin:6px 0;font-size:0.82em">
          <strong>Zone direction = STRIDE rule</strong><br>
          <span style="color:#666">Examples: HTTPS requests, SQL queries, Kafka messages, BLE</span>
        </div>
        <div style="font-size:0.82em;color:#555;margin-top:8px">
          <strong>STRIDE exposure by direction:</strong><br>
          ↑ Less→More critical: Tampering<br>
          ↓ More→Less critical: Information Disclosure<br>
          Zone-0 source: + DoS
        </div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")

    # Component breakdown for this workshop
    st.subheader(f"📦 {scenario['title']} – DFD Elements")

    comp_types = {"external_entity": [], "process": [], "datastore": []}
    for comp in scenario["components"]:
        comp_types[comp["type"]].append(comp)

    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("**👤 Interactors (External Entities)**")
        for comp in comp_types["external_entity"]:
            st.markdown(f"""<div class="component-card">
            <strong>{comp['name']}</strong><br>
            <small>{comp['description']}</small>
            </div>""", unsafe_allow_html=True)
    with col2:
        st.markdown("**⚙️ Modules (Processes)**")
        for comp in comp_types["process"]:
            st.markdown(f"""<div class="component-card">
            <strong>{comp['name']}</strong><br>
            <small>{comp['description']}</small>
            </div>""", unsafe_allow_html=True)
    with col3:
        st.markdown("**💾 Modules (Data Stores)**")
        for comp in comp_types["datastore"]:
            st.markdown(f"""<div class="component-card">
            <strong>{comp['name']}</strong><br>
            <small>{comp['description']}</small>
            </div>""", unsafe_allow_html=True)

    st.markdown("---")
    st.subheader("🔗 Connections (Data Flows)")

    # ── Key concept callout ───────────────────────────────────────────────
    st.markdown("""
    <div class="key-concept">
      <h4>Key Concept: Why Data Flows Are the Heart of Threat Modeling</h4>
      <p style="margin:0;font-size:0.95em">Every security failure ultimately involves data moving somewhere it shouldn't,
      or being modified somewhere it shouldn't. Data flows are where <strong>Tampering</strong>,
      <strong>Information Disclosure</strong>, and <strong>Denial of Service</strong> threats
      are discovered. The protocol matters too — HTTPS is encrypted,
      plain HTTP is not. MQTT/BLE in IoT may have no authentication at all.</p>
    </div>
    """, unsafe_allow_html=True)

    flows_df = pd.DataFrame([{
        "Source": f["source"], "→": "→", "Destination": f["destination"],
        "Data Type": f["data"], "Protocol": f["protocol"]
    } for f in scenario["data_flows"]])
    st.dataframe(flows_df, use_container_width=True, hide_index=True)

    # Trust boundaries callout
    if scenario.get("trust_boundaries"):
        st.markdown("---")
        st.subheader("🚧 Trust Boundaries")
        st.markdown("""
        <div class="info-box">
        <strong>What is a Trust Boundary?</strong><br>
        A trust boundary is any line in your diagram where data crosses from one level of trust
        to another — from the internet to your frontend, from your API to your database.
        <strong>Every trust boundary crossing is a potential attack surface.</strong>
        The more critical the zone on the receiving side, the higher the threat potential.
        </div>
        """, unsafe_allow_html=True)
        for tb in scenario["trust_boundaries"]:
            st.markdown(f"""
            <div class="component-card">
            <strong>🚧 {tb['name']}</strong><br>
            <span style="color:#555;font-size:0.9em">{tb['description']}</span><br>
            <span style="font-size:0.82em;color:#777">Components: {', '.join(tb['components'])}</span>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("""
    <div class="practical-task">
    <strong>🎯 Step 1 Complete</strong> – You now have a complete picture of the system design:<br>
    • All <strong>Interactors</strong> (external entities) identified<br>
    • All <strong>Modules</strong> (processes + data stores) listed<br>
    • All <strong>Connections</strong> (data flows) documented with protocols<br><br>
    Next: Apply <strong>Zones of Trust</strong> to every component using the 0–9 criticality scale.
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    st.subheader("🗺️ Your Data-Flow Diagram")
    st.markdown("""
    <div class="info-box">
    The architecture is now simplified into <b>DFD notation</b>: <b>rectangle</b> = external entity (E) &nbsp;|&nbsp;
    <b>oval</b> = process (P) &nbsp;|&nbsp; <b>parallel lines</b> = data store (D) &nbsp;|&nbsp; <b>arrow</b> = data flow (F).
    The IDs are used in every later step. The next stage draws trust boundaries on top of this diagram.
    </div>
    """, unsafe_allow_html=True)
    diag_tabs = st.tabs(["🗺️ Data-flow diagram", "📊 Elements & flows (with IDs)"])
    with diag_tabs[0]:
        show_architecture_diagram(current_workshop, mode="dfd", key_suffix="s2_dfd")
    with diag_tabs[1]:
        _eid = element_ids(current_workshop["scenario"])
        st.dataframe(pd.DataFrame([{"ID": _eid[c["name"]], "Element": c["name"], "Type": KIND_LABEL[c["type"]],
                                    "Description": c["description"]} for c in current_workshop["scenario"]["components"]]),
                     use_container_width=True, hide_index=True)
        st.markdown("**Data flows:**")
        st.dataframe(pd.DataFrame([{"ID": _eid[_flow_key(f)], "Flow": _flow_key(f), "Data": f["data"], "Protocol": f["protocol"]}
                                   for f in current_workshop["scenario"]["data_flows"]]), use_container_width=True, hide_index=True)

    nav_buttons(1, "", 3, "", key="p2")


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 3 · STAGE 2 DFD — ZONES OF TRUST
# ─────────────────────────────────────────────────────────────────────────────
elif st.session_state.current_step == 3:
    st.header("Step 4 (cont.): Apply Zones of Trust")
    scope_reminder()

    st.markdown("""
    <div class="methodology-step">
    <strong>🏷️ Infosec Step 2: Apply Zones of Trust</strong><br>
    Every component in your DFD must be labeled with a <strong>criticality zone</strong>.
    Zones indicate how sensitive/trusted a component is, using both a <em>label</em> 
    (e.g., "Critical") and a <em>numerical score</em> (0–9).<br><br>
    <strong>Why this matters:</strong> The <em>direction</em> of data flows between zones 
    determines which STRIDE categories apply — this is the mechanical heart of the methodology.
    </div>
    """, unsafe_allow_html=True)

    # ZONE SCALE EXPLANATION
    st.subheader("🏷️ The Criticality Zone Scale")
    st.markdown("*(From the Infosec Institute threat modeling methodology)*")

    zone_cols = st.columns(3)
    zone_list = list(CRITICALITY_ZONES.items())
    for i, (zone_name, zinfo) in enumerate(zone_list):
        col = zone_cols[i % 3]
        with col:
            st.markdown(f"""
            <div style="background:{zinfo['color']};padding:12px;border-radius:6px;
                        border:2px solid {zinfo['border']};margin:6px 0">
                <strong>{zone_name}</strong><br>
                <span style="font-size:1.3em;font-weight:bold">Score: {zinfo['range']}</span><br>
                <small>{zinfo['description']}</small><br>
                <small><em>Examples: {zinfo['examples']}</em></small><br>
                <small style="color:#555">STRIDE: {zinfo['stride_applicability']}</small>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("---")

    # PRACTICAL LABELLING EXERCISE
    st.subheader("🎯 Practical Exercise: Label Your System Components")

    st.markdown("""
    <div style="background:#FDF7E3;border-radius:10px;
                padding:18px 22px;border:2px dashed #ECAB13;margin:12px 0">
    <div style="font-size:0.75em;font-weight:700;text-transform:uppercase;letter-spacing:2px;
                color:#D55611;margin-bottom:8px">🎯 PRACTICAL EXERCISE — ZONE LABELLING</div>
    <p style="margin:0 0 10px 0;color:#333;font-size:0.95em">
    For each component, ask yourself three questions before selecting a zone:
    </p>
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;font-size:0.85em">
      <div style="background:white;border-radius:6px;padding:10px;border-left:3px solid #D55611">
        <strong style="color:#D55611">1. Who controls it?</strong><br>
        <span style="color:#555">Your org = higher zone. External party = Zone 0.</span>
      </div>
      <div style="background:white;border-radius:6px;padding:10px;border-left:3px solid #D55611">
        <strong style="color:#D55611">2. What data passes through?</strong><br>
        <span style="color:#555">PII/financial/health = higher zone. Public content = lower.</span>
      </div>
      <div style="background:white;border-radius:6px;padding:10px;border-left:3px solid #D55611">
        <strong style="color:#D55611">3. What's the breach impact?</strong><br>
        <span style="color:#555">Life-safety/regulatory = Zone 7–9. Minor = Zone 1–3.</span>
      </div>
    </div>
    <p style="margin:10px 0 0 0;color:#666;font-size:0.85em">
    After submitting, you'll see the correct zones and — more importantly — <strong>why</strong> each 
    component belongs there. The reasoning matters more than memorizing the answer.
    </p>
    </div>
    """, unsafe_allow_html=True)

    scenario = current_workshop["scenario"]
    zone_options = list(CRITICALITY_ZONES.keys())

    with st.form("zone_labelling_form"):
        user_zone_labels = {}
        user_zone_scores_input = {}

        # Group by type so students see external entities together, then processes, then stores
        type_groups = {
            "external_entity": ("👤 External Entities — Zone 0 (Not in Control)", []),
            "process":         ("⚙️ Processes — Your Application Components", []),
            "datastore":       ("💾 Data Stores — Persistence Layer", []),
        }
        for comp in scenario["components"]:
            t = comp.get("type","process")
            if t in type_groups:
                type_groups[t][1].append(comp)

        for ttype, (group_label, group_comps) in type_groups.items():
            if not group_comps:
                continue
            st.markdown(f"#### {group_label}")
            st.markdown(f"""
            <div class="info-box" style="margin:4px 0 10px 0;padding:8px 14px">
            <small>{"External entities are always Zone 0 — they are outside your system control. Assign scores 0–1." if ttype=="external_entity" else
                    "Processes receive and transform data. Consider: what data flows through here? What is the impact if compromised?" if ttype=="process" else
                    "Data stores persist sensitive information. Consider: what data is stored? What regulations apply?"}</small>
            </div>
            """, unsafe_allow_html=True)
            cols_zone = st.columns(min(len(group_comps), 3))
            for i, comp in enumerate(group_comps):
                with cols_zone[i % min(len(group_comps), 3)]:
                    st.markdown(f"""
                    <div style="background:#FAFAF9;border:1px solid #E9E8E6;border-radius:8px;
                                padding:10px 12px;margin:0 0 8px 0">
                    <strong>{comp['name']}</strong><br>
                    <small style="color:#80796B">{comp['description']}</small>
                    </div>
                    """, unsafe_allow_html=True)
                    user_zone_labels[comp['name']] = st.selectbox(
                        f"Zone:",
                        zone_options,
                        key=f"zone_label_{comp['name']}",
                        help="What criticality zone does this component belong to?"
                    )
                    user_zone_scores_input[comp['name']] = st.slider(
                        f"Score (0–9):",
                        0, 9, 0 if ttype=="external_entity" else 3,
                        key=f"zone_score_{comp['name']}"
                    )
            st.markdown("---")

        submitted_zones = st.form_submit_button(
            "✅ Submit Zone Labels & See Results", type="primary", use_container_width=True
        )

    if submitted_zones or st.session_state.get('zone_labelling_done'):
        if submitted_zones:
            st.session_state.zone_labels = user_zone_labels
            st.session_state.zone_scores = user_zone_scores_input
            st.session_state.zone_labelling_done = True
            save_progress()

        st.markdown("---")
        st.subheader("📊 Zone Label Results & Explanation")

        correct_count = 0
        total_comps = len(scenario["components"])

        for comp in scenario["components"]:
            name = comp["name"]
            correct_zone = comp.get("zone", "Standard Application")
            correct_score = comp.get("zone_score", 3)
            user_zone_val = st.session_state.zone_labels.get(name, "")
            user_score_val = st.session_state.zone_scores.get(name, 0)
            zone_match = user_zone_val == correct_zone
            score_close = abs(user_score_val - correct_score) <= 1

            if zone_match:
                correct_count += 1
                status = "✅"
                css_class = "correct-answer"
            elif score_close:
                status = "⚠️"
                css_class = "partial-answer"
            else:
                status = "❌"
                css_class = "incorrect-answer"

            zinfo = CRITICALITY_ZONES.get(correct_zone, {})
            zone_color = zinfo.get('color','#F6F5F4')
            zone_border = zinfo.get('border','#A6A196')
            st.markdown(f"""
            <div class="{css_class}" style="margin:6px 0">
            <div style="display:flex;justify-content:space-between;align-items:flex-start">
              <div>
                {status} <strong>{name}</strong>
                &nbsp;·&nbsp; <span style="font-size:0.85em">
                  Your: <em>{user_zone_val}</em> (z{user_score_val})
                  &nbsp;→&nbsp;
                  Correct: <strong style="color:{"#347737" if zone_match else "#BA3434"}">{correct_zone}</strong> (z{correct_score})
                </span>
              </div>
            </div>
            <div style="margin-top:8px;font-size:0.88em;color:#444">
              <strong>Why {correct_zone}:</strong> {comp.get("zone_rationale", comp["description"])}
            </div>
            <div style="margin-top:6px;font-size:0.82em;color:#666">
              <strong>STRIDE exposure:</strong> {zinfo.get("stride_applicability","Check zone-direction rules")}
            </div>
            </div>
            """, unsafe_allow_html=True)

        score_pct = correct_count / total_comps * 100
        st.markdown(f"""
        <div class="{'score-excellent' if score_pct>=80 else 'score-good' if score_pct>=60 else 'score-fair'}">
        Zone Labelling Score: {correct_count}/{total_comps} ({score_pct:.0f}%)
        </div>
        """, unsafe_allow_html=True)

        st.markdown("---")
        st.subheader("📊 Zone-Labeled DFD")

        st.markdown("""
        <div class="info-box">
        The diagram below shows the correct zone assignments for all components.
        The zone boundaries (the dotted lane dividers and Z-chips) are where data crosses trust levels —
        these are the highest-risk areas for your threat analysis in Step 3.
        </div>
        """, unsafe_allow_html=True)

        show_architecture_diagram(current_workshop, mode="zones", key_suffix="s2_zones")

        # Trust boundaries explanation
        st.markdown("---")
        st.subheader("🔒 Trust Boundaries – Where Threats Are Born")

        st.markdown("""
        A **trust boundary** is a line in your DFD that separates components of different 
        criticality zones. When data crosses a trust boundary:
        - The **direction** (up or down in zone score) determines which STRIDE threats apply
        - **Zone 0 → any zone**: Always check Spoofing and DoS
        - **Lower zone → Higher zone**: Always check Tampering
        - **Higher zone → Lower zone**: Always check Information Disclosure
        """)

        for boundary in scenario["trust_boundaries"]:
            with st.expander(f"🔐 {boundary['name']}", expanded=True):
                st.markdown(f"**Crossing:** {boundary['description']}")
                if boundary.get("components"):
                    st.markdown(f"**Components at boundary:** {', '.join(boundary['components'])}")
                # Find relevant flows for this boundary
                boundary_comps = set(boundary.get("components", []))
                relevant_flows = [
                    f for f in scenario["data_flows"]
                    if f["source"] in boundary_comps or f["destination"] in boundary_comps
                ]
                if relevant_flows:
                    st.markdown("**Flows crossing this boundary:**")
                    for rf in relevant_flows:
                        src_score = next((c["zone_score"] for c in scenario["components"] if c["name"] == rf["source"]), 0)
                        dst_score = next((c["zone_score"] for c in scenario["components"] if c["name"] == rf["destination"]), 0)
                        direction = "📈 less→more critical (⚠ Tampering risk)" if dst_score > src_score else "📉 more→less critical (⚠ Info Disclosure risk)"
                        st.markdown(f"  → **{rf['source']}** → **{rf['destination']}**: {rf['data']} ({rf['protocol']}) — {direction}")

        st.markdown("""
        <div class="practical-task">
        <strong>✅ Step 2 Complete</strong><br>
        You have applied criticality zones to all components. Now you can use zone direction 
        to <strong>mechanically derive</strong> which STRIDE threats apply to each flow and node.
        This is the key insight from the Infosec methodology: 
        STRIDE is not guesswork — it follows rules.
        </div>
        """, unsafe_allow_html=True)

    nav_buttons(2, "⬅️ Back to Design", 4, "Next: STRIDE Rules ➡️", key="p3")


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 4 · STAGE 3 STRIDE — ZONE RULES
# ─────────────────────────────────────────────────────────────────────────────
elif st.session_state.current_step == 4:
    st.header("Step 5 (cont.): STRIDE Zone Rules & Threat Discovery")
    scope_reminder()

    st.markdown("""
    <div class="methodology-step">
    <strong>🔍 Infosec Step 3 (Theory): STRIDE Discovery Rules</strong><br>
    STRIDE threats are not discovered by intuition — they are <em>derived mechanically</em> 
    from your zone-labeled DFD using a specific set of rules. Once you know the zones, 
    you know exactly which STRIDE categories apply to each element.
    </div>
    """, unsafe_allow_html=True)

    # WORKED EXAMPLE first — teach before quizzing
    st.subheader("🎓 Worked Example: How a Professional Derives Threats")

    st.markdown("""
    <div style="background:#1D1C1A;color:#F3F3F2;padding:20px 24px;
                border-radius:10px;border-left:5px solid #70D6C8;margin:12px 0">
    <div style="font-size:0.72em;font-weight:700;text-transform:uppercase;letter-spacing:2px;
                color:#70D6C8;margin-bottom:10px">📚 WORKED EXAMPLE — READ THIS BEFORE THE QUIZ</div>
    <p style="margin:0 0 12px 0;font-size:0.95em;color:#DEDDDA">
    A professional does NOT look at a system and guess threats. They follow a mechanical process.
    Here is exactly how to think through every flow and node.</p>
    <hr style="border-color:rgba(255,255,255,0.15);margin:10px 0">

    <strong style="color:#A4E5DC">Scenario:</strong>
    <span style="color:#DEDDDA"> Customer Browser (Zone 0) → Web Frontend (Zone 1) → Database (Zone 7)</span><br><br>

    <strong style="color:#A4E5DC">Step 1 — Identify the flow direction:</strong><br>
    <span style="color:#DEDDDA">
    Flow A: Browser → Frontend = Zone 0 → Zone 1 = score 0 → score 1 = <strong style="color:#F2B45A">GOING UP</strong><br>
    Flow B: Frontend → Database = Zone 1 → Zone 7 = score 1 → score 7 = <strong style="color:#F2B45A">GOING UP</strong>
    </span><br><br>

    <strong style="color:#A4E5DC">Step 2 — Apply the zone-direction rules:</strong><br>
    <span style="color:#DEDDDA">
    Going UP (less→more critical) = <strong style="color:#F2B45A">TAMPERING</strong> applies<br>
    Flow A source = Zone 0 (external) = <strong style="color:#F2B45A">DoS + SPOOFING</strong> also apply
    </span><br><br>

    <strong style="color:#A4E5DC">Step 3 — Check node rules for the destination (Web Frontend):</strong><br>
    <span style="color:#DEDDDA">
    Reachable from Zone 0? Yes → <strong style="color:#F2B45A">SPOOFING</strong> applies<br>
    Connected to lower-zone node (Browser zone 0)? Yes → <strong style="color:#F2B45A">EoP</strong> applies<br>
    SPOOFING + TAMPERING both apply? Yes → <strong style="color:#F2B45A">REPUDIATION</strong> also applies
    </span><br><br>

    <strong style="color:#70D6C8">Result for Flow A (Browser→Frontend):</strong>
    <span style="color:#DEDDDA"> Tampering, DoS, Spoofing</span><br>
    <strong style="color:#70D6C8">Result for Web Frontend node:</strong>
    <span style="color:#DEDDDA"> Spoofing, Tampering, Repudiation, DoS, EoP</span><br>
    <strong style="color:#70D6C8">Result for Flow B (Frontend→Database):</strong>
    <span style="color:#DEDDDA"> Tampering (1→7 = going up, no Zone 0 source)</span>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    # STRIDE RULES REFERENCE TABLE
    st.subheader("📜 The STRIDE Zone-Direction Rules (Reference)")

    st.markdown("""
    <div class="stride-rule-box">
    <strong>Now you know the pattern.</strong> Apply the same logic below:
    check zone scores, check direction, check Zone-0 status, check node adjacency.
    </div>
    """, unsafe_allow_html=True)

    # Flows rules
    st.markdown("#### 🔗 Rules for Connections (Data Flows)")

    flow_rules_data = [
        ["Tampering (T)", "Less critical → More critical zone",
         "Attacker at lower trust injects malicious data flowing into higher-trust system",
         "Zone 1 (Frontend) → Zone 7 (Database): SQL injection risk"],
        ["Information Disclosure (I)", "More critical → Less critical zone",
         "Sensitive data flowing outward may be captured or leaked",
         "Zone 7 (Database) → Zone 0 (User): PII exposed in API response"],
        ["Denial of Service (D)", "Zone 0 (External) → Any other zone",
         "External actors with no trust can flood any entry point they reach",
         "Zone 0 (User) → Zone 3 (API): Request flooding exhausts resources"]
    ]
    for rule_row in flow_rules_data:
        stride_cat, trigger, rationale, example = rule_row
        st.markdown(f"""
        <div class="stride-rule-box">
        <strong>⚡ {stride_cat}</strong><br>
        <strong>Applies when:</strong> {trigger}<br>
        <strong>Why:</strong> {rationale}<br>
        <strong>Example:</strong> <em>{example}</em>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("#### 🔵 Rules for Nodes (Interactors, Processes, Data Stores)")

    node_rules_data = [
        ["Spoofing (S)", "Any node reachable by a Zone 0 (Not in Control) entity",
         "External actors can impersonate legitimate users/systems at any reachable node",
         "Login page reachable from Internet: Attacker impersonates valid user"],
        ["Repudiation (R)", "Any node where BOTH Spoofing AND Tampering apply",
         "If identity can be faked AND data modified, actions can be performed untraceably",
         "API server with user input: Orders placed, then denied as fake"],
        ["Denial of Service (D)", "Any node reachable by a Zone 0 entity",
         "External actors can exhaust resources of any node they can reach",
         "Public API endpoint: Botnet flood crashes the service"],
        ["Elevation of Privilege (E)", "Any node connected to a lower-criticality-zone node",
         "Attacker who compromises lower zone may gain higher-zone capabilities",
         "Admin API (zone 5) reachable from regular API (zone 3): Privilege escalation"]
    ]
    for rule_row in node_rules_data:
        stride_cat, trigger, rationale, example = rule_row
        st.markdown(f"""
        <div class="stride-rule-box">
        <strong>⚡ {stride_cat}</strong><br>
        <strong>Applies when:</strong> {trigger}<br>
        <strong>Why:</strong> {rationale}<br>
        <strong>Example:</strong> <em>{example}</em>
        </div>
        """, unsafe_allow_html=True)

    # STRIDE PER ELEMENT TYPE
    st.markdown("---")
    st.subheader("📊 STRIDE per DFD Element Type (Quick Reference)")

    stride_matrix = pd.DataFrame({
        "Element Type": ["External Entity (Interactor)", "Process (Module)",
                         "Data Flow (Connection)", "Data Store (Module)"],
        "S – Spoofing": ["✓ YES (zone 0)", "✓ YES", "✓ YES", "— Rare"],
        "T – Tampering": ["— No", "✓ YES", "✓ YES (less→more)", "✓ YES"],
        "R – Repudiation": ["✓ YES", "✓ YES", "— No", "✓ YES"],
        "I – Info Disclosure": ["— No", "✓ YES", "✓ YES (more→less)", "✓ YES"],
        "D – Denial of Svc": ["— No", "✓ YES", "✓ YES (zone 0)", "✓ YES"],
        "E – Elev Privilege": ["— No", "✓ YES", "— No", "— No"]
    })
    st.dataframe(stride_matrix, use_container_width=True, hide_index=True)

    # INTERACTIVE STRIDE RULES EXERCISE
    st.markdown("---")
    st.subheader("🎯 Practical Exercise: Apply STRIDE Rules to Your Architecture")

    scenario = current_workshop["scenario"]
    st.markdown(f"""
    <div class="practical-task">
    <strong>Your Task:</strong> For each data flow below, identify which STRIDE categories apply 
    based on the zone direction rules you just learned. Select all that apply.
    </div>
    """, unsafe_allow_html=True)

    # Build correct answers per flow
    stride_flow_answers = {}
    for flow in scenario["data_flows"][:4]:  # First 4 flows for exercise
        src_comp = next((c for c in scenario["components"] if c["name"] == flow["source"]), None)
        dst_comp = next((c for c in scenario["components"] if c["name"] == flow["destination"]), None)
        if not src_comp or not dst_comp:
            continue
        src_score = src_comp.get("zone_score", 3)
        dst_score = dst_comp.get("zone_score", 3)
        correct = []
        if dst_score > src_score:
            correct.append("Tampering")
        if src_score > dst_score:
            correct.append("Information Disclosure")
        if src_score == 0:
            correct.append("Denial of Service")
            correct.append("Spoofing")
        stride_flow_answers[f"{flow['source']} → {flow['destination']}"] = {
            "correct": correct,
            "src_zone": src_comp.get("zone"), "src_score": src_score,
            "dst_zone": dst_comp.get("zone"), "dst_score": dst_score,
            "flow": flow
        }

    with st.form("stride_rules_form"):
        user_stride_selections = {}
        for flow_key, flow_info in stride_flow_answers.items():
            fl = flow_info["flow"]
            st.markdown(f"**Flow: {flow_key}** — {fl['data']} ({fl['protocol']})")
            st.caption(f"From: **{flow_info['src_zone']}** (score {flow_info['src_score']}) → "
                       f"To: **{flow_info['dst_zone']}** (score {flow_info['dst_score']})")
            user_stride_selections[flow_key] = st.multiselect(
                f"Which STRIDE categories apply to this flow?",
                ["Spoofing", "Tampering", "Repudiation", "Information Disclosure",
                 "Denial of Service", "Elevation of Privilege"],
                key=f"stride_ex_{flow_key}"
            )
            st.markdown("---")

        submitted_stride = st.form_submit_button(
            "✅ Check My STRIDE Rules Analysis", type="primary", use_container_width=True
        )

    col_retry_s, _ = st.columns([1,4])
    with col_retry_s:
        if st.session_state.get('stride_rules_submitted'):
            if st.button("🔄 Retry STRIDE Rules Quiz", key="retry_stride"):
                st.session_state.stride_rules_submitted = False
                st.session_state.stride_rules_answers = {}
                st.rerun()

    if submitted_stride or st.session_state.get('stride_rules_submitted'):
        if submitted_stride:
            st.session_state.stride_rules_answers = user_stride_selections
            st.session_state.stride_rules_submitted = True
            save_progress()

        st.markdown("---")
        st.subheader("📋 STRIDE Rules Exercise Results")

        total_correct = 0
        total_questions = len(stride_flow_answers)

        for flow_key, flow_info in stride_flow_answers.items():
            correct_set = set(flow_info["correct"])
            user_set = set(st.session_state.stride_rules_answers.get(flow_key, []))
            fl = flow_info["flow"]

            matches = correct_set == user_set
            if matches:
                total_correct += 1
                status_class = "correct-answer"
                status_icon = "✅"
            else:
                status_class = "partial-answer" if correct_set & user_set else "incorrect-answer"
                status_icon = "⚠️" if correct_set & user_set else "❌"

            # Build the rule explanation
            rule_explanation = []
            if "Tampering" in correct_set:
                rule_explanation.append(f"**Tampering**: {flow_info['src_zone']} (zone {flow_info['src_score']}) → {flow_info['dst_zone']} (zone {flow_info['dst_score']}) — less→more critical")
            if "Information Disclosure" in correct_set:
                rule_explanation.append(f"**Information Disclosure**: {flow_info['src_zone']} (zone {flow_info['src_score']}) → {flow_info['dst_zone']} (zone {flow_info['dst_score']}) — more→less critical")
            if "Denial of Service" in correct_set:
                rule_explanation.append(f"**Denial of Service**: Source is Zone 0 (Not in Control) — can flood any target")
            if "Spoofing" in correct_set:
                rule_explanation.append(f"**Spoofing**: Zone 0 (external entity) can impersonate legitimate users at this entry point")

            st.markdown(f"""
            <div class="{status_class}">
            {status_icon} <strong>{flow_key}</strong> — {fl['data']}<br>
            Your answer: {', '.join(user_set) if user_set else 'None'}<br>
            Correct: <strong>{', '.join(correct_set) if correct_set else 'None'}</strong><br><br>
            <strong>Why these categories apply:</strong><br>
            {"<br>".join(["• " + r for r in rule_explanation]) if rule_explanation else "• No STRIDE categories apply to this flow based on zone rules"}
            </div>
            """, unsafe_allow_html=True)

        score_pct = total_correct / total_questions * 100 if total_questions else 0
        st.markdown(f"""
        <div class="{'score-excellent' if score_pct>=80 else 'score-good' if score_pct>=60 else 'score-fair'}">
        STRIDE Rules Score: {total_correct}/{total_questions} ({score_pct:.0f}%)
        </div>
        """, unsafe_allow_html=True)

    with st.expander("🗺️ See the zone-direction hints on your own architecture", expanded=True):
        show_architecture_diagram(current_workshop, mode="zonerules", key_suffix="p4_zr")

    st.markdown("""
    <div class="practical-task">
    <strong>✅ STRIDE rules understood</strong><br>
    Use zone relationships to prioritise STRIDE hypotheses. Validate each against data, identities, privileges and abuse cases; zone rules are prompts, not proof or an exhaustive list.
    Next: build an <strong>attack tree</strong> to see <em>how</em> an attacker would reach the threat, then identify your own threats.
    </div>
    """, unsafe_allow_html=True)
    nav_buttons(3, "⬅️ Back to Zones", 5, "Next: Build Attack Tree ➡️", key="p4")


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 5 · STAGE 3 STRIDE — ATTACK TREE
# ─────────────────────────────────────────────────────────────────────────────
elif st.session_state.current_step == 5:
    st.header("🌳 Step 5 (cont.): Attack Tree")
    scope_reminder()

    st.markdown("""
    <div class="info-box">
    <h3>📚 What is an Attack Tree and How Does it Complement STRIDE?</h3>
    An <strong>Attack Tree</strong> shows HOW an attacker would exploit the STRIDE threats 
    you identified using zone rules. While STRIDE tells you WHAT threats exist, 
    attack trees show the step-by-step path an attacker takes.<br><br>
    <strong>The connection to your zones:</strong> Each leaf node in the attack tree 
    corresponds to a zone boundary crossing in your DFD.
    </div>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("""
        ### Node Types
        **🎯 Goal Node (Root)** – Attacker's ultimate objective (PINK)  
        **AND Gate** – ALL child steps must succeed (BLUE)  
        **OR Gate** – ANY child path succeeds (GREEN)  
        **🟡 Leaf Nodes** – Specific attack steps with difficulty ratings
        
        ### Difficulty Ratings
        🔴 **Easy** – Automated tools, no skill needed  
        🟡 **Medium** – Some technical knowledge required  
        🟢 **Hard** – Expert skills or expensive resources  
        """)
    with col2:
        st.markdown("""
        ### How to Use Attack Trees with Zone Analysis
        
        1. **Start at Zone 0** – Attacker always begins outside your system
        2. **Trace zone crossings** – Each attack step crosses a trust boundary
        3. **AND gates = defense in depth** – Breaking one step blocks the path
        4. **OR gates = multiple attack surfaces** – Each must be defended
        5. **Easy leaf nodes = highest priority** – Attackers choose the path of least resistance
        """)

    st.markdown("---")
    st.subheader(f"📊 Attack Tree: {current_workshop['architecture_type']}")

    attack_tree_data = ATTACK_TREES.get(st.session_state.selected_workshop, {})
    if attack_tree_data:
        st.markdown(f"""
        <div class="learning-box">
        <strong>{attack_tree_data['title']}</strong><br>
        {attack_tree_data['description']}
        </div>
        """, unsafe_allow_html=True)

        # HOW TO READ AN ATTACK TREE — before showing it
        st.markdown("""
        <div style="background:#2D6B63;color:white;
                    padding:18px 22px;border-radius:10px;margin:10px 0;border-left:5px solid #89BBB5">
        <div style="font-size:0.7em;font-weight:700;text-transform:uppercase;letter-spacing:2px;
                    color:#AACFCA;margin-bottom:10px">HOW TO READ THIS ATTACK TREE</div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
        <div>
          <strong style="color:#A4E5DC">🎯 GOAL node (root, pink)</strong><br>
          <span style="font-size:0.88em;color:#DAD8D4">The attacker's final objective. Everything below is a path toward this goal.</span>
        </div>
        <div>
          <strong style="color:#A4E5DC">🔵 OR gates (green)</strong><br>
          <span style="font-size:0.88em;color:#DAD8D4">ANY child path succeeds = goal reached. Each OR branch is a separate attack surface you must defend.</span>
        </div>
        <div>
          <strong style="color:#A4E5DC">🔗 AND gates (blue)</strong><br>
          <span style="font-size:0.88em;color:#DAD8D4">ALL children must succeed. Block ANY single step → entire path blocked. This is defense-in-depth.</span>
        </div>
        <div>
          <strong style="color:#A4E5DC">🟡 Leaf nodes</strong><br>
          <span style="font-size:0.88em;color:#DAD8D4">Atomic attack steps. <strong style="color:#E9A0A0">Easy</strong>=automated tools, no skill. <strong style="color:#F5E980">Medium</strong>=technical knowledge. <strong style="color:#A9D2AA">Hard</strong>=expert + resources.</span>
        </div>
        </div>
        <hr style="border-color:rgba(255,255,255,0.2);margin:12px 0">
        <strong style="color:#A4E5DC">Prioritization rule:</strong>
        <span style="color:#DAD8D4"> Find the path with the most "Easy" leaf nodes and the fewest AND gates.
        That is your highest-priority fix — it's the cheapest attack and provides the most options to the attacker.</span>
        </div>
        """, unsafe_allow_html=True)

        with st.spinner("Generating attack tree..."):
            tree_img = generate_attack_tree(json.dumps(attack_tree_data["tree"]), attack_tree_data["title"])

        if tree_img:
            st.image(f"data:image/png;base64,{tree_img}",
                     caption=attack_tree_data["title"], use_column_width=True)

        st.markdown("---")
        st.subheader("🔍 Connecting Attack Tree to Zone Analysis")

        ws_id = st.session_state.selected_workshop
        scenario = current_workshop["scenario"]

        if ws_id == "1":
            st.markdown("""
            ### Attack Tree → Zone Boundary Analysis for TechMart

            | Attack Path | Zone Crossing | STRIDE Rule | Priority |
            |---|---|---|---|
            | API Key Exposure | Zone 3 (API) → Zone 0 (Public) | Information Disclosure (more→less) | 🔴 **CRITICAL** – 3 Easy steps |
            | XSS + Session Hijack | Zone 0 → Zone 1 then Zone 1 → Zone 3 | Tampering (less→more) + Spoofing | 🟡 **HIGH** – Medium+Easy+Easy |
            | SQL Injection | Zone 1 → Zone 3 → Zone 7 | Tampering (less→more × 2 zone jumps) | 🟡 **HIGH** – stops at validation |
            | Admin Panel Exploit | Zone 1 → Zone 3 (admin) | Elevation of Privilege | 🟡 **HIGH** – auth bypass needed |
            | MITM Attack | Zone 0 → Zone 1 | Tampering on entry flow | 🟢 **LOWER** – Hard positioning step |

            **Key insight**: The API Key Exposure path has 3 consecutive "Easy" steps and crosses from 
            Zone 3 to Zone 0 (high→low, Information Disclosure). This is your **#1 priority**.
            """)
        elif ws_id == "2":
            st.markdown("""
            ### Attack Tree → Zone Boundary Analysis for CloudBank

            | Attack Path | Zone Crossing | STRIDE Rule | Priority |
            |---|---|---|---|
            | BOLA Attack | Zone 1 (Gateway) → Zone 5 (Payment) | Information Disclosure (ownership bypass) | 🔴 **CRITICAL** – Easy+Easy+Medium |
            | Service Impersonation | Zone 5 → Zone 5 (no mTLS) | Spoofing (same zone, no mutual auth) | 🟡 **HIGH** – needs cluster access |
            | Replay Transaction | Zone 5 internal | Tampering (replayed message) | 🟡 **HIGH** – Medium+Easy+Easy |
            | Rate Limit Bypass | Zone 0 → Zone 1 | DoS (Zone 0 to any) | 🟡 **HIGH** – distributed attack |

            **Key insight**: BOLA (Broken Object Level Authorization) is the #1 OWASP API risk 
            because the zone boundary exists but ownership checks are missing from the flow.
            """)
        elif ws_id == "3":
            st.markdown("""
            ### Attack Tree → Zone Boundary Analysis for DataInsight

            | Attack Path | Zone Crossing | STRIDE Rule | Priority |
            |---|---|---|---|
            | Request Body Injection | Zone 0 → Zone 2 (missing JWT check) | Tampering + EoP (tenant boundary bypass) | 🔴 **CRITICAL** – Medium+Easy+Easy |
            | SQL Injection (remove filter) | Zone 3 (Query Svc) → Zone 8 (DW) | Tampering (zone 3→8, less→more) | 🔴 **CRITICAL** – Easy+Medium+Easy |
            | Kafka Cross-Read | Zone 5 (Kafka, no ACL) → Zone 3 | Information Disclosure (zone 5→3) | 🟡 **HIGH** – Medium+Easy+Easy |
            | JWT Token Tampering | Zone 0 → Zone 2 | Spoofing + Tampering | 🟢 **LOWER** – Hard+Hard (crypto) |

            **Key insight**: Both "Critical" paths have Easy leaf nodes that cross the tenant isolation boundary.
            Database-level Row-Level Security (RLS) blocks BOTH SQL paths at the zone boundary.
            """)
        elif ws_id == "4":
            st.markdown("""
            ### Attack Tree → Zone Boundary Analysis for HealthMonitor

            | Attack Path | Zone Crossing | STRIDE Rule | Priority |
            |---|---|---|---|
            | Replay Normal Readings | Zone 1 (Gateway) → Zone 4 (Cloud) | Tampering (less→more, replayed data) | 🔴 **LIFE-CRITICAL** – Medium+Easy+Easy |
            | Alert Flooding DoS | Zone 4 → Zone 9 (Alert Svc) | DoS on life-critical zone | 🔴 **LIFE-CRITICAL** – Hard+Easy+Easy |
            | BLE MITM Attack | Zone 0 → Zone 1 | Tampering (entry boundary) | 🔴 **CRITICAL** – Easy+Medium+Medium |
            | Physical Firmware Mod | Zone 0 → Zone 1 | Tampering (physical boundary, zone 0) | 🟡 **HIGH** – Medium+Hard+Medium+Easy |
            | HL7 Injection | Zone 3 → Zone 0 (Legacy EHR) | Tampering (unprotected external) | 🟡 **HIGH** – Medium+Medium+Easy+Easy |

            **Key insight**: When zone 9 (Maximum Security) is involved, even a "Hard" first step 
            becomes unacceptable risk — life-safety requires blocking ALL paths.
            """)

    nav_buttons(4, "⬅️ Back to STRIDE Rules", 6, "Ready: Identify Threats ➡️", key="p5")


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 6 · STAGE 3 STRIDE — IDENTIFY THREATS
# ─────────────────────────────────────────────────────────────────────────────
elif st.session_state.current_step == 6:
    st.header("Step 5 (cont.): Identify Threats with STRIDE")
    scope_reminder()

    st.markdown(f"""
    <div class="info-box">
    <strong>⚡ Stage 5 · STRIDE — apply the zone rules to your DFD</strong><br>
    For each threat: (1) pick the <strong>component or flow</strong> affected, (2) apply the zone-direction rule to choose the
    <strong>STRIDE category</strong>. Be specific — “attacker alters the order total in the API call”, not just “tampering”.<br>
    ATT&amp;CK mapping (Stage 6), scoring (Stage 7) and controls (Stage 8) come next, using the threats you identify here.<br><br>
    <strong>Goal:</strong> identify {current_workshop['target_threats']} threats
    </div>
    """, unsafe_allow_html=True)

    # Show quick STRIDE rules reference
    with st.expander("📋 Quick Reference: STRIDE Zone Rules", expanded=False):
        st.markdown("""
        **Flow rules (check zone direction):**
        - **Tampering**: Less-critical → More-critical (score goes UP)
        - **Info Disclosure**: More-critical → Less-critical (score goes DOWN)
        - **DoS**: Zone 0 → Any zone

        **Node rules:**
        - **Spoofing**: Node reachable by Zone 0 entity
        - **Repudiation**: Node where Spoofing + Tampering both apply
        - **DoS**: Node reachable by Zone 0
        - **Elevation of Privilege**: Node connected to lower-zone node
        """)

    # ── Live architecture diagram showing currently affected components ─────
    st.subheader("🗺️ Live Architecture Map")
    st.markdown("""
    <div class="info-box">
    This diagram updates as you analyze threats. Affected components are highlighted in red with a ⚠ badge.
    Use this to understand <em>where</em> each threat sits in the architecture.
    </div>
    """, unsafe_allow_html=True)
    live_tabs = st.tabs(["🏗️ Current Threat Map", "🔵 STRIDE & Threat Actors", "🏗️ Clean Architecture"])
    with live_tabs[0]:
        show_architecture_diagram(current_workshop, threats=st.session_state.threats, mode="threat", key_suffix="step4_live", editable=True, default_kind="threat")
    with live_tabs[1]:
        show_architecture_diagram(current_workshop, threats=st.session_state.threats, mode="stride", key_suffix="step4_stride")
    with live_tabs[2]:
        show_architecture_diagram(current_workshop, mode="architecture", key_suffix="step4_arch")

    st.markdown("---")
    # Already-analyzed threat IDs — prevents duplicate inflation
    analyzed_ids = {a["matched_threat_id"] for a in st.session_state.user_answers}
    remaining_threats = [t for t in workshop_threats if t["id"] not in analyzed_ids]

    if not remaining_threats:
        st.success("✅ All threats for this workshop have been analyzed!")
    else:
        st.markdown(f"""
        <div style="background:#F1F0EF;padding:10px 16px;border-radius:8px;border-left:4px solid #3CAFA0;margin:8px 0">
        <strong>Progress: {len(analyzed_ids)}/{current_workshop['target_threats']} threats analyzed</strong>
        &nbsp;·&nbsp; {len(remaining_threats)} remaining
        </div>
        """, unsafe_allow_html=True)

    with st.form("threat_selection_form"):
        st.subheader("➕ Identify a Threat Scenario")

        available_threats = remaining_threats if remaining_threats else workshop_threats
        threat_options = {f"{t_['id']}: {t_['threat'][:65]}...": t_ for t_ in available_threats}
        if not threat_options:
            st.error("No threats available for this workshop")
            st.stop()

        selected_threat_key = st.selectbox(
            "Choose a threat scenario to analyze:", list(threat_options.keys()),
            help="Each threat can only be identified once. Select from the remaining threats.")
        selected_predefined = threat_options[selected_threat_key]

        st.markdown(f"""
        <div class="stride-rule-box">
        <strong>Zone context for this threat:</strong><br>
        From zone: <strong>{selected_predefined.get('zone_from', 'N/A')}</strong> →
        To zone: <strong>{selected_predefined.get('zone_to', 'N/A')}</strong>
        </div>
        """, unsafe_allow_html=True)

        zf, zt = selected_predefined.get("zone_from", ""), selected_predefined.get("zone_to", "")
        comps_ = current_workshop["scenario"]["components"]
        if zf and zt:
            fs = next((c.get("zone_score", 3) for c in comps_ if c["name"] == zf.replace(" Zone", "")),
                      CRITICALITY_ZONES.get(zf, {}).get("score", 3))
            ts = next((c.get("zone_score", 3) for c in comps_ if c["name"] == zt.replace(" Zone", "")),
                      CRITICALITY_ZONES.get(zt, {}).get("score", 3))
            if fs < ts:
                direction_hint = "⬆ Flow goes **less → more** critical zone → primary risk: **Tampering**"
            elif fs > ts:
                direction_hint = "⬇ Flow goes **more → less** critical zone → primary risk: **Information Disclosure**"
            else:
                direction_hint = "↔ Flow within the **same zone** → check node-level rules (Spoofing, EoP)"
            if fs == 0:
                direction_hint += " | Zone-0 source → also watch for **Denial of Service** and **Spoofing**"
        else:
            direction_hint = "Review the zone labels to determine the applicable STRIDE rule."
        st.markdown(f"""
        <div class="stride-rule-box">
        <strong>🧭 Zone-Direction Guidance:</strong> {direction_hint}<br>
        <em>Use this rule to select the most appropriate STRIDE category below.</em>
        </div>
        """, unsafe_allow_html=True)

        all_options = [c["name"] for c in comps_] + [f"{f['source']} → {f['destination']}" for f in current_workshop["scenario"]["data_flows"]]
        c_a, c_b = st.columns(2)
        user_component = c_a.selectbox("Which component/flow is affected?", ["— select —"] + all_options, index=0)
        user_stride = c_b.selectbox(
            "STRIDE category — apply the zone-direction rule:",
            ["— select —", "Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"],
            index=0)

        _actors = get_actors()
        _alabel = {a["id"]: f"{a['id']} — {a['label']}" for a in _actors}
        user_actors = st.multiselect("Which threat actor(s) would carry this out? (recommended)", list(_alabel.keys()),
                                     format_func=lambda i: _alabel[i], key="w_ident_actors")

        st.markdown("#### 🧩 Write a real-world threat statement")
        st.caption("Scaffold: threat source + prerequisites + action → impact + affected assets. Tailor the wording to this scenario and record evidence/assumptions.")
        threat_source = st.text_input("Threat source / actor", value=", ".join([_alabel.get(i, i) for i in user_actors]),
                                      placeholder="e.g. authenticated but malicious customer", key="w_threat_source")
        prerequisites = st.text_input("Prerequisites / conditions", placeholder="e.g. API trusts a caller-supplied object ID", key="w_threat_prereq")
        threat_action = st.text_input("Attacker action", placeholder="e.g. changes the object ID in a request", key="w_threat_action")
        threat_impact = st.text_input("Consequence / impact", placeholder="e.g. reads another customer's order", key="w_threat_impact")
        impacted_assets = st.text_input("Impacted assets / security properties", placeholder="e.g. customer order data; confidentiality", key="w_threat_assets")
        statement_rationale = st.text_area("Evidence and assumptions (what supports this?)",
                                           placeholder="Reference the flow, trust boundary, identity, privilege or assumption. State what still needs validation.",
                                           max_chars=600, key="w_threat_rationale", height=75)

        if st.form_submit_button("✅ Record threat & get STRIDE feedback", type="primary", use_container_width=True):
            errs = []
            if user_component == "— select —":
                errs.append("Select a component or data flow")
            if user_stride == "— select —":
                errs.append("Select a STRIDE category")
            if errs:
                st.error("⚠️ Please complete all selections: " + " · ".join(errs))
            else:
                _rec = new_record(user_component, user_stride, selected_predefined)
                _rec["actors"] = list(user_actors)
                _rec["threat_source"] = threat_source.strip()
                _rec["prerequisites"] = prerequisites.strip()
                _rec["threat_action"] = threat_action.strip()
                _rec["threat_impact"] = threat_impact.strip()
                _rec["impacted_assets"] = impacted_assets.strip()
                _rec["statement_rationale"] = statement_rationale.strip()
                if all([_rec["threat_source"], _rec["prerequisites"], _rec["threat_action"],
                        _rec["threat_impact"], _rec["impacted_assets"]]):
                    _rec["threat_statement"] = (
                        f"A {_rec['threat_source']} with {_rec['prerequisites']} can {_rec['threat_action']}, "
                        f"which may lead to {_rec['threat_impact']}, negatively impacting {_rec['impacted_assets']}."
                    )
                st.session_state.user_answers.append(_rec)
                sync_labels_from_analysis(False)
                recalc_totals()
                save_progress()
                st.rerun()

    render_identified_threats()

    if st.session_state.user_answers and st.button("🏷️ Add my identified threats to the diagram labels", key="w_sync_threats"):
        n_added = sync_labels_from_analysis(include_controls=False)
        save_progress()
        st.rerun()

    st.progress(min(len(st.session_state.user_answers) / current_workshop['target_threats'], 1.0))
    if len(st.session_state.user_answers) < current_workshop['target_threats']:
        st.info(f"⚠️ {current_workshop['target_threats'] - len(st.session_state.user_answers)} more threats needed to complete this workshop.")
    else:
        st.success("✅ All required threats identified — continue to scoring.")

    nav_buttons(5, "⬅️ Back to Attack Tree", 7, "Next: Score the risk ➡️", bool(st.session_state.user_answers),
                "Identify at least one threat first.", key="p6")


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 7 · STAGE 4 SCORING (NEW)
# ─────────────────────────────────────────────────────────────────────────────
elif st.session_state.current_step == 7:
    render_scoring_page()


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 8 · STAGE 5 CONTROLS — OWASP MAPPING
# ─────────────────────────────────────────────────────────────────────────────
elif st.session_state.current_step == 8:
    st.header("Step 8 (start): Map STRIDE Threats to Controls")
    scope_reminder()
    st.markdown("""
    <div class="methodology-step">
    <strong>🛡️ Stage 8 · Controls</strong><br>
    Before you pick controls for your own threats, learn how each STRIDE category maps to OWASP Top 10 risks and to the
    four control categories: <strong>🧱 Guardrails</strong>, <strong>🧪 Filtering</strong>, <strong>🔑 Access rules</strong>
    and <strong>📡 Monitoring</strong>.
    </div>
    """, unsafe_allow_html=True)

    # OWASP MAPPING SECTION
    st.markdown("---")
    st.subheader("🛡️ STRIDE → OWASP Top 10 Mapping")

    st.markdown("""
    <div class="methodology-step">
    <strong>🛡️ Infosec Step 4: Explore Mitigations (OWASP)</strong><br>
    Once threats are identified via STRIDE, you select mitigations from the 
    <strong>OWASP Top 10</strong> list. The table below shows which OWASP vulnerability 
    categories map to each STRIDE threat category — this is how professionals translate 
    threat categories into concrete security controls.
    </div>
    """, unsafe_allow_html=True)

    for stride_cat, owasp_info in OWASP_STRIDE_MAP.items():
        with st.expander(f"🔗 {stride_cat} → {' + '.join(owasp_info['owasp'])}", expanded=False):
            st.markdown(f"""
            <div class="owasp-box">
            <strong>OWASP Mapping:</strong> {', '.join(owasp_info['owasp'])}<br><br>
            <strong>Why these OWASP categories map to {stride_cat}:</strong><br>
            {owasp_info['owasp_detail']}
            </div>
            """, unsafe_allow_html=True)

            st.markdown("**OWASP-recommended controls:**")
            for ctrl in owasp_info["controls"]:
                st.markdown(f"• {ctrl}")

    # PRACTICAL OWASP MAPPING EXERCISE
    st.markdown("---")
    st.subheader("🎯 Practical Exercise: Map STRIDE to OWASP Controls")

    st.markdown("""
    <div class="practical-task">
    <strong>Your Task:</strong> For each STRIDE category below, select the correct OWASP Top 10 vulnerability 
    that maps to it. This tests whether you understand the <em>relationship</em> between threat categories 
    and vulnerability classifications.
    </div>
    """, unsafe_allow_html=True)

    owasp_exercise = {
        "Spoofing": {
            "question": """An e-commerce site lets users log in with just a username — no password required. 
            An attacker logs in as any customer by guessing their username. 
            Which OWASP 2021 category does this vulnerability fall under?""",
            "options": [
                "A01 — Broken Access Control (users can access other users' orders)",
                "A07 — Identification and Authentication Failures (broken login = impersonation possible)",
                "A03 — Injection (attacker injects a fake identity into the session)",
                "A05 — Security Misconfiguration (the login form is misconfigured)",
            ],
            "correct": "A07 — Identification and Authentication Failures (broken login = impersonation possible)",
            "explanation": "When authentication is weak or absent, attackers can impersonate legitimate users. This is STRIDE Spoofing, enabled by OWASP A07 – Identification and Authentication Failures. The fix is strong MFA + session management."
        },
        "Tampering": {
            "question": """A shopping cart API accepts this URL: /cart?item_id=5&price=1.00
            A customer changes price=1.00 to price=0.01 and buys a £500 laptop for 1p.
            Which OWASP category and STRIDE threat does this represent?""",
            "options": [
                "Information Disclosure + A02 — they exposed the price field in the URL",
                "Elevation of Privilege + A01 — the user bypassed pricing access controls",
                "Tampering + A04 — the system was insecurely designed to trust client-supplied price data",
                "Spoofing + A07 — the user spoofed a lower price to the server",
            ],
            "correct": "Tampering + A04 — the system was insecurely designed to trust client-supplied price data",
            "explanation": "Never trust client-supplied data for security decisions like pricing. This is Tampering (modifying data in transit/at input). OWASP A04 – Insecure Design covers systems that have no security controls at the design level. The fix: compute price server-side from a trusted catalog, never from user input."
        },
        "Information Disclosure": {
            "question": """A hospital database backup is stored in an S3 bucket. The bucket is private but
            the backup files are not encrypted. An AWS misconfiguration briefly makes the bucket public.
            All patient records are readable. Which OWASP category is the ROOT CAUSE?""",
            "options": [
                "A05 — Security Misconfiguration (the bucket was briefly public)",
                "A02 — Cryptographic Failures (data was unencrypted, so exposure = full disclosure)",
                "A01 — Broken Access Control (the bucket access control was broken)",
                "A09 — Security Logging and Monitoring Failures (nobody noticed the exposure)",
            ],
            "correct": "A02 — Cryptographic Failures (data was unencrypted, so exposure = full disclosure)",
            "explanation": "A05 (misconfiguration) was the trigger, but the ROOT CAUSE of Information Disclosure is A02 – Cryptographic Failures. If data at rest were encrypted (AES-256), a brief public exposure would expose ciphertext not plaintext. Defense-in-depth means you fix BOTH, but the Information Disclosure STRIDE threat maps to A02 as the primary control."
        },
        "Repudiation": {
            "question": """A bank employee transfers £2M to a fraudulent account. When investigated, 
            the bank discovers the transaction logs were stored in the same database as transactions — 
            and had been deleted. The employee denies all knowledge.
            Which OWASP category enables this Repudiation attack?""",
            "options": [
                "A04 — Insecure Design (the system should have been designed with separate audit logs)",
                "A07 — Authentication Failures (the employee was authenticated, so authentication failed)",
                "A09 — Security Logging and Monitoring Failures (logs deleted = no audit trail = Repudiation)",
                "A01 — Broken Access Control (the employee accessed records they shouldn't have)",
            ],
            "correct": "A09 — Security Logging and Monitoring Failures (logs deleted = no audit trail = Repudiation)",
            "explanation": "Repudiation requires both the act AND the absence of proof. A09 – Security Logging and Monitoring Failures is the direct enabler: without immutable, out-of-band audit logs (e.g., append-only SIEM, WORM storage), there is no non-repudiation. A04 is a contributing issue but A09 is the specific OWASP category that maps to STRIDE Repudiation."
        }
    }

    with st.form("owasp_mapping_form"):
        user_owasp_answers = {}
        for stride_q, q_data in owasp_exercise.items():
            st.markdown(f"**{stride_q} Scenario:** {q_data['question']}")
            user_owasp_answers[stride_q] = st.radio(
                f"Select the correct answer:",
                q_data["options"],
                key=f"owasp_q_{stride_q}",
                index=None
            )
            st.markdown("---")

        submitted_owasp = st.form_submit_button(
            "✅ Submit OWASP Mapping Answers", type="primary", use_container_width=True
        )

    col_retry_o, _ = st.columns([1,4])
    with col_retry_o:
        if st.session_state.get('owasp_mapping_submitted'):
            if st.button("🔄 Retry OWASP Quiz", key="retry_owasp"):
                st.session_state.owasp_mapping_submitted = False
                st.session_state.owasp_mapping_answers = {}
                st.rerun()

    if submitted_owasp or st.session_state.get('owasp_mapping_submitted'):
        if submitted_owasp:
            st.session_state.owasp_mapping_answers = user_owasp_answers
            st.session_state.owasp_mapping_submitted = True
            save_progress()

        st.markdown("---")
        st.subheader("📋 OWASP Mapping Results")
        owasp_correct = 0
        for stride_q, q_data in owasp_exercise.items():
            user_ans = st.session_state.owasp_mapping_answers.get(stride_q, "")
            is_correct = user_ans == q_data["correct"]
            if is_correct:
                owasp_correct += 1
            css = "correct-answer" if is_correct else "incorrect-answer"
            icon = "✅" if is_correct else "❌"
            st.markdown(f"""
            <div class="{css}">
            {icon} <strong>{stride_q}</strong><br>
            Your answer: {user_ans or 'Not answered'}<br>
            Correct: <strong>{q_data['correct']}</strong><br>
            <em>{q_data['explanation']}</em>
            </div>
            """, unsafe_allow_html=True)

        owasp_pct = owasp_correct / len(owasp_exercise) * 100
        st.markdown(f"""
        <div class="{'score-excellent' if owasp_pct>=80 else 'score-good' if owasp_pct>=60 else 'score-fair'}">
        OWASP Mapping Score: {owasp_correct}/{len(owasp_exercise)} ({owasp_pct:.0f}%)
        </div>
        """, unsafe_allow_html=True)

    nav_buttons(7, "⬅️ Back to Scoring", 9, "Next: Select controls ➡️", key="p8")


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 9 · STAGE 5 CONTROLS — SELECT CONTROLS (NEW)
# ─────────────────────────────────────────────────────────────────────────────
elif st.session_state.current_step == 9:
    render_controls_page()


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 10 · STAGE 6 RESIDUAL RISK (NEW)
# ─────────────────────────────────────────────────────────────────────────────
elif st.session_state.current_step == 10:
    render_residual_page()


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 11 · STAGE 7 REVIEW PLAN (NEW)
# ─────────────────────────────────────────────────────────────────────────────
elif st.session_state.current_step == 11:
    render_review_plan_page()


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 12 · STAGE 7 REVIEW — ASSESSMENT & REPORT
# ─────────────────────────────────────────────────────────────────────────────
elif st.session_state.current_step == 12:
    st.header("Step 10 (cont.): Assessment & Threat-Mapped Architecture Review")
    recalc_totals()
    scope_reminder()

    if not st.session_state.user_answers:
        st.warning("No answers to assess")
        if st.button("⬅️ Back"):
            go_page(6)
        st.stop()

    final_pct = st.session_state.total_score / st.session_state.max_score * 100

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Score", f"{st.session_state.total_score}/{st.session_state.max_score}")
    col2.metric("Percentage", f"{final_pct:.1f}%")
    col3.metric("Threats Analyzed", len(st.session_state.user_answers))
    col4.metric("Grade", "A" if final_pct >= 90 else "B" if final_pct >= 80
                else "C" if final_pct >= 70 else "D" if final_pct >= 60 else "F")

    st.markdown("---")
    st.subheader("🗺️ Architecture & Threat Assessment Diagrams")

    st.markdown("""
    <div class="learning-box">
    These diagrams show your complete threat-mapped architecture.
    <b>Red nodes/edges</b> = you identified threats there.
    <b>Coloured letters (S T R I D E)</b> = the STRIDE categories you mapped to each element.
    </div>
    """, unsafe_allow_html=True)

    assess_diag_tabs = st.tabs([
        "🔴 Threat-Highlighted Map",
        "🔵 STRIDE-Annotated Map",
        "🏗️ Clean Architecture",
        "🏷️ Zone-Labelled DFD",
        "🎯 ATT&CK Map"
    ])
    with assess_diag_tabs[0]:
        show_architecture_diagram(current_workshop,
                                  threats=st.session_state.threats,
                                  mode="threat", key_suffix="s5_threat", editable=True)
    with assess_diag_tabs[1]:
        show_architecture_diagram(current_workshop,
                                  threats=st.session_state.threats,
                                  mode="stride", key_suffix="s5_stride")
    with assess_diag_tabs[2]:
        show_architecture_diagram(current_workshop,
                                  mode="architecture", key_suffix="s5_arch")
    with assess_diag_tabs[3]:
        show_architecture_diagram(current_workshop, threats=st.session_state.threats,
                                  mode="zones", key_suffix="s6_zones")
    with assess_diag_tabs[4]:
        show_architecture_diagram(current_workshop, mode="mitre", key_suffix="s6_mitre")

    st.markdown("---")
    st.subheader("📋 10-Stage Threat Model Review")
    render_stage_review()

    # PERFORMANCE
    st.markdown("---")
    st.subheader("📊 Performance Analysis")

    correct_count = sum(1 for a in st.session_state.user_answers if a["score"]/a["max_score"] >= 0.8)
    partial_count = sum(1 for a in st.session_state.user_answers if 0.5 <= a["score"]/a["max_score"] < 0.8)
    incorrect_count = sum(1 for a in st.session_state.user_answers if a["score"]/a["max_score"] < 0.5)

    col1, col2, col3 = st.columns(3)
    col1.metric("Excellent (80%+)", correct_count)
    col2.metric("Partial (50-79%)", partial_count)
    col3.metric("Needs Review (<50%)", incorrect_count)

    # RECOMMENDATIONS
    st.subheader("📚 Learning Recommendations")
    if final_pct < 70:
        st.warning("""
        **Areas to Review:**
        - Go back and redo the Zone Labelling exercise
        - Study the STRIDE zone direction rules carefully
        - Review OWASP → STRIDE mapping table
        - For each wrong answer, trace the zone boundary direction
        """)
    elif final_pct < 90:
        st.info("""
        **To Reach Mastery:**
        - Fine-tune zone direction analysis (less→more vs more→less)
        - Study the OWASP control specifics for your weaker STRIDE categories
        - Review feedback on partial answers
        """)
    else:
        st.success("""
        **🏆 Excellent – Methodology Mastered!**
        - Strong zone-based threat identification
        - Correct STRIDE category selection using rules
        - Good OWASP control mapping
        - Ready for next workshop!
        """)

    # EXPORT
    st.markdown("---")
    st.subheader("📥 Export Your Threat Model")
    st.markdown("""
    <div class="info-box">
    <strong>Two exports available:</strong><br>
    • <strong>Your Submission PDF</strong>: Your analysis with zone labels, STRIDE rules, OWASP mappings, and scores<br>
    • <strong>Complete Reference PDF</strong>: All threats with full 4-step methodology documentation
    </div>
    """, unsafe_allow_html=True)

    results_df = pd.DataFrame([{
        "Threat_ID": a["matched_threat_id"],
        "Component": a["component"],
        "STRIDE": a["stride"],
        "Zone_Rule": a.get("predefined_threat", {}).get("stride_rule_applied", ""),
        "OWASP": ", ".join(a.get("predefined_threat", {}).get("owasp_categories", [])),
        "Likelihood": a["likelihood"],
        "Impact": a["impact"],
        "Risk_1to9": rec_risk(a) or "",
        "Residual_1to9": rec_residual(a) or "",
        "Decision": (a.get("residual") or {}).get("decision", ""),
        "Score": f"{a['score']}/{a['max_score']} ({a['score']/a['max_score']*100:.0f}%)",
        "Mitigations": ", ".join(a.get('selected_mitigations', [])),
        "Threat_Statement": a.get("threat_statement", ""),
        "Threat_Source": a.get("threat_source", ""),
        "Prerequisites": a.get("prerequisites", ""),
        "Threat_Action": a.get("threat_action", ""),
        "Threat_Impact": a.get("threat_impact", ""),
        "Impacted_Assets": a.get("impacted_assets", ""),
        "Statement_Rationale": a.get("statement_rationale", ""),
        "ATTACK_Techniques": ", ".join(a.get("mitre", [])),
        "ATTACK_Path": a.get("mitre_note", ""),
        "CAPEC_Patterns": ", ".join(a.get("capec", [])),
        "CAPEC_Rationale": a.get("capec_rationale", ""),
        "Likelihood_Rationale": a.get("likelihood_rationale", ""),
        "Impact_Rationale": a.get("impact_rationale", "")
    } for a in st.session_state.user_answers])

    col1, col2, col3 = st.columns(3)
    with col1:
        st.download_button(
            "📥 CSV Results (with OWASP)",
            results_df.to_csv(index=False),
            f"stride_results_ws{st.session_state.selected_workshop}_{datetime.now().strftime('%Y%m%d')}.csv",
            "text/csv", use_container_width=True
        )
    with col2:
        if st.button("📄 Generate My Threat Model PDF", use_container_width=True):
            with st.spinner("Building PDF..."):
                user_pdf = generate_user_threat_model_pdf(
                    current_workshop, st.session_state.user_answers,
                    st.session_state.total_score, st.session_state.max_score, extra=build_pdf_extra()
                )
            if user_pdf:
                st.download_button(
                    "⬇️ Download My PDF",
                    user_pdf,
                    f"my_threat_model_ws{st.session_state.selected_workshop}_{datetime.now().strftime('%Y%m%d')}.pdf",
                    "application/pdf", use_container_width=True,
                    key="dl_user_pdf"
                )
            else:
                st.error("PDF generation failed")
    with col3:
        if st.button("📚 Generate Complete Reference PDF", use_container_width=True):
            with st.spinner("Building reference PDF (may take ~10s)..."):
                complete_pdf = generate_complete_threat_model_pdf(
                    current_workshop, st.session_state.selected_workshop
                )
            if complete_pdf:
                st.download_button(
                    "⬇️ Download Reference PDF",
                    complete_pdf,
                    f"complete_model_ws{st.session_state.selected_workshop}_{datetime.now().strftime('%Y%m%d')}.pdf",
                    "application/pdf", use_container_width=True,
                    key="dl_complete_pdf"
                )
            else:
                st.error("PDF generation failed")

    nav_buttons(11, "⬅️ Back to Review plan", 13, "Complete Workshop ➡️", key="p12")


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 13 · STAGE 7 REVIEW — COMPLETE
# ─────────────────────────────────────────────────────────────────────────────
elif st.session_state.current_step == 13:
    recalc_totals()
    # Mark completed
    if st.session_state.selected_workshop not in st.session_state.completed_workshops:
        st.session_state.completed_workshops.add(st.session_state.selected_workshop)
        save_progress()

    final_pct  = st.session_state.total_score / st.session_state.max_score * 100 if st.session_state.max_score > 0 else 0
    grade      = "A+" if final_pct >= 95 else "A" if final_pct >= 90 else "B" if final_pct >= 80 else "C" if final_pct >= 70 else "D" if final_pct >= 60 else "F"
    grade_grad = ("#AB8118" if final_pct >= 90 else
                  "#205924" if final_pct >= 80 else
                  "#D55611" if final_pct >= 70 else
                  "#B23D19")

    if final_pct >= 90:
        st.balloons()

    # ── Certificate-style completion banner ─────────────────────────────────
    from datetime import date
    today = date.today().strftime("%B %d, %Y")
    st.markdown(f"""
    <div style="background:#1D1C1A;border-radius:14px;
                padding:32px 36px;text-align:center;box-shadow:0 6px 24px rgba(0,0,0,0.3);
                border:2px solid rgba(255,255,255,0.1)">
      <div style="color:#A4E5DC;font-size:0.85em;text-transform:uppercase;letter-spacing:2px;margin-bottom:8px">
        Certificate of Completion
      </div>
      <h1 style="color:white;margin:0 0 8px 0;font-size:2em">🏆 {current_workshop['name']}</h1>
      <div style="color:#C0EAE4;font-size:1em;margin-bottom:16px">
        {current_workshop['scenario']['title']} · {current_workshop['level']}
      </div>
      <div style="display:inline-block;background:{grade_grad};color:white;
                  padding:12px 32px;border-radius:30px;font-size:1.8em;font-weight:700;
                  box-shadow:0 3px 12px rgba(0,0,0,0.4);margin-bottom:16px">
        Grade: {grade} &nbsp;|&nbsp; {final_pct:.1f}%
      </div>
      <div style="color:#A4E5DC;font-size:0.85em">{today}</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    # ── Score metrics ───────────────────────────────────────────────────────
    c1,c2,c3,c4,c5 = st.columns(5)
    c1.metric("Score", f"{st.session_state.total_score}/{st.session_state.max_score}")
    c2.metric("Percentage", f"{final_pct:.1f}%")
    c3.metric("Grade", grade)
    c4.metric("Threats", len(st.session_state.user_answers))
    correct_ct = sum(1 for a in st.session_state.user_answers if a["score"]/a["max_score"] >= 0.8)
    c5.metric("Correct", f"{correct_ct}/{len(st.session_state.user_answers)}")

    # ── 7-stage mastery review ──────────────────────────────────────────────
    st.markdown("---")
    st.subheader("📋 10-Stage Threat Modeling Summary")
    render_stage_summary()

    # ── Skills unlocked ─────────────────────────────────────────────────────
    ws_skill_map = {
        "1": ["DFD element classification","Zone assignment (0–7)","Basic STRIDE zone rules","OWASP A01–A10 mapping","XSS/SQLi/IDOR identification"],
        "2": ["Service mesh threat modeling","mTLS & service spoofing","BOLA (API1:2023)","Distributed tracing for Repudiation","OWASP API Security Top 10"],
        "3": ["Multi-tenant isolation design","Cross-tenant EoP","Row-Level Security","SOC 2 / ISO 27001 mapping","Shared infrastructure threats"],
        "4": ["IoT/edge trust boundaries","Replay attack design","HIPAA / FDA 21 CFR compliance","Life-critical (Zone 9) threat modeling","HL7 v2 injection"],
    }
    new_skills = ws_skill_map.get(st.session_state.selected_workshop, [])
    if new_skills:
        st.markdown("---")
        st.subheader("🔓 Skills Unlocked This Workshop")
        cols_sk = st.columns(3)
        for i, sk in enumerate(new_skills):
            cols_sk[i%3].markdown(f"""
            <div style="background:#F1F0EF;padding:10px 14px;
                        border-radius:8px;border-left:4px solid #3CAFA0;margin:4px 0;font-size:0.88em">
              🔓 <strong>{sk}</strong>
            </div>
            """, unsafe_allow_html=True)

    # ── Personalised improvement areas ──────────────────────────────────────
    st.markdown("---")
    st.subheader("📈 Personalised Feedback")

    wrong_answers = [a for a in st.session_state.user_answers if a["score"]/a["max_score"] < 0.8]
    if wrong_answers:
        st.markdown("""<div class="warning-box"><strong>Areas to review before moving on:</strong></div>""", unsafe_allow_html=True)
        for wa in wrong_answers:
            pred = wa.get("predefined_threat", {})
            pct_w = wa["score"]/wa["max_score"]*100
            st.markdown(f"""
            <div style="background:#FAFAFA;border-left:4px solid #E35E5C;border-radius:8px;
                        padding:12px 16px;margin:6px 0">
              <strong>{wa['matched_threat_id']}</strong> — {pred.get('stride','')} on {pred.get('component','')}
              &nbsp;({pct_w:.0f}%)<br>
              <small style="color:#555">Review: {pred.get('stride_rule_applied','')}</small>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.markdown("""<div class="success-box"><strong>🎯 Perfect execution — no areas flagged for review!</strong></div>""", unsafe_allow_html=True)

    # Next workshop
    st.markdown("---")
    next_ws = str(int(st.session_state.selected_workshop) + 1)
    if next_ws in WORKSHOPS:
        next_config = WORKSHOPS[next_ws]
        st.info(f"""
        **Ready for Workshop {next_ws}?**

        **{next_config['name']}** – {next_config['level']}

        New concepts introduced:
        {"".join(f"• {lo}" + chr(10) for lo in next_config.get('learning_objectives', [])[:3])}

        *(Ask your instructor for the unlock code)*
        """)
        if is_workshop_unlocked(next_ws):
            if st.button(f"Start Workshop {next_ws} ➡️", type="primary", use_container_width=True):
                start_workshop(next_ws)
                save_progress()
                st.rerun()
    else:
        st.success("🏆 **All Workshops Completed! Full 10-Stage Process Mastered!**")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("📊 Review Assessment", use_container_width=True):
            go_page(12)
    with col2:
        if st.button("🏠 Return to Home", use_container_width=True):
            st.session_state.selected_workshop = None
            st.session_state.current_step = 1
            save_progress()
            st.rerun()

st.markdown("---")
st.caption("STRIDE Threat Modeling Learning Lab | Scope → Architecture → DFD → Trust boundaries → STRIDE → ATT&CK → Scoring → Controls → Residual risk → Review")
