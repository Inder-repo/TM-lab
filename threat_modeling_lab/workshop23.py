"""
Threat Modeling Lab - nine-step end-to-end methodology (refactored).

Run:  streamlit run workshop23.py

Architecture (see docs/ARCHITECTURE.md):
  workshop23.py  entry point: page config, CSS, unlock codes, sidebar, tracker, routing
  ui_common.py   session state, persistence wiring, form/key helpers
  ui_pages.py    the nine canonical steps (one page per step)
  tm_model.py    canonical data model and all business rules (no Streamlit)
  tm_assess.py   completion gates, discover-first reveal gate, rubric, integrity checks
  tm_export.py   JSON / CSV / Markdown / PDF exports from the same model
  tm_catalog.py  ATT&CK / CAPEC datasets with provenance + verifier
  tm_labs.py     per-lab pedagogy (scaffolding, briefs, instructor-only gaps)
  lab_data.py    scenarios and instructor reference threats (never used as an answer key)
"""
import hashlib
import hmac

import streamlit as st

import tm_assess as a
import tm_journey
import tm_labs
import tm_model as m
from lab_data import WORKSHOPS

st.set_page_config(page_title="Threat Modeling Lab", page_icon="\U0001F512", layout="wide", initial_sidebar_state="expanded")

# Unlock codes are stored only as salted SHA-256 digests (unchanged from the legacy app).
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

# ── state ─────────────────────────────────────────────────────────────────────────────
from ui_common import S, go, init_state, ws, save, select_lab, show_flash, tm  # noqa: E402
from ui_pages import PAGES  # noqa: E402

init_state()
SHORT = ["Scope", "DFD", "STRIDE", "Boundaries", "ATT&CK / CAPEC", "Inherent risk", "Controls", "Residual", "Review"]
LEVEL_ICON = {"Foundation": "\U0001F331", "Intermediate": "\U0001F33F", "Advanced": "\U0001F333", "Expert": "\U0001F525"}


def unlocked(lab):
    return lab in tm()["unlocked_labs"]


def lab_selector():
    st.markdown("### Labs")
    for lab, cfg in WORKSHOPS.items():
        prof = tm_labs.profile(lab)
        is_cur = tm()["selected_lab"] == lab
        done = lab in tm()["completed_labs"]
        c1, c2 = st.columns([4, 1])
        marker = "\u25B6 " if is_cur else ""
        if c1.button(f"{marker}Lab {lab}: {prof['role']}", key=f"lab_{lab}", disabled=not unlocked(lab), use_container_width=True):
            select_lab(lab)
            st.rerun()
        c2.write("\u2705" if done else ("" if unlocked(lab) else "\U0001F512"))
        if not unlocked(lab):
            with st.expander(f"Unlock lab {lab}"):
                code = st.text_input("Unlock code", type="password", key=f"code_{lab}")
                if st.button("Unlock", key=f"unlock_{lab}"):
                    if verify_unlock_code(lab, code):
                        tm()["unlocked_labs"] = sorted(set(tm()["unlocked_labs"]) | {lab})
                        save()
                        st.rerun()
                    else:
                        st.error("That code is not valid.")


def home():
    st.markdown("""<div class="hero"><div class="eyebrow">Threat modeling lab</div>
    <h1>End-to-end threat modelling in four labs</h1>
    <p>Nine steps, one canonical model: scope, DFD, STRIDE, trust boundaries, ATT&amp;CK/CAPEC, inherent risk, controls, residual risk and review.</p>
    <div class="chips"><span class="chip">4 progressive labs</span><span class="chip">Evidence-based risk reduction</span><span class="chip">Traceable IDs</span><span class="chip">JSON / CSV / report exports</span></div></div>""", unsafe_allow_html=True)
    if S.get("_load_warning"):
        st.warning(S["_load_warning"])
    for lab, cfg in WORKSHOPS.items():
        prof = tm_labs.profile(lab)
        sc = cfg["scenario"]
        st.markdown(f"#### {LEVEL_ICON.get(cfg['level'], '')} Lab {lab}: {sc['title']} - *{prof['role']}*")
        st.write(f"{sc['description']} \u00b7 {cfg['level']} \u00b7 {cfg['duration']}")
        st.caption(prof["purpose"])
    st.markdown("**The nine steps (every lab):** " + " \u2192 ".join(f"{n}. {t}" for n, t, _ in a.STEPS))
    if st.button("\u25B6 Start Lab 1", type="primary", use_container_width=True):
        select_lab("1")
        st.rerun()


def tracker(w):
    prog = a.progress(w)
    cur = tm()["current_step"]
    parts = []
    for p, label in zip(prog, SHORT):
        state = "done" if p["state"] == "complete" else ("active" if p["step"] == cur else "todo")
        dot = "\u2713" if p["state"] == "complete" else str(p["step"])
        parts.append(f'<div class="stg stg-{state}"><div class="stg-dot">{dot}</div><div class="stg-label">{label}</div></div>')
    st.markdown('<div class="stepper">' + '<div class="stg-line"></div>'.join(parts) + "</div>", unsafe_allow_html=True)
    done = sum(1 for p in prog if p["state"] == "complete")
    st.progress(done / 9)
    st.caption(f"Step {cur} of 9 \u00b7 {done} complete \u00b7 completion is judged on artefact quality, not time spent")


def sidebar():
    with st.sidebar:
        st.markdown('<div class="brand"><div class="logo">\U0001F512</div><div class="name">Threat Modeling Lab</div></div>', unsafe_allow_html=True)
        st.markdown("---")
        lab_selector()
        if tm()["selected_lab"]:
            w = ws()
            prof = tm_labs.profile(w["lab_id"])
            st.markdown("---")
            nxt = tm_journey.next_actions(w)[0]
            if nxt["code"] != "done":
                if st.button(f"\u25B6 Next: {nxt['headline']}", key=f"nxt_{w['lab_id']}", type="primary", use_container_width=True, help=nxt["detail"]):
                    go(nxt["step"])
            if st.button("\U0001F9ED Journey overview", key=f"jo_{w['lab_id']}", use_container_width=True):
                go(0)
            prog = {p["step"]: p for p in a.progress(w)}
            for ph_name, _tag, steps_ in tm_journey.PHASES:
                st.markdown(f"**{ph_name}**")
                for n in steps_:
                    p = prog[n]
                    icon = {"complete": "\u2705", "blocked": "\u26D4", "in_progress": "\U0001F7E1", "not_started": "\u26AA"}[p["state"]]
                    if st.button(f"{icon} {n} \u00b7 {SHORT[n - 1]}", key=f"nav_{w['lab_id']}_{n}", use_container_width=True):
                        go(n)
            st.markdown("---")
            locked = prof["assist_locked"]
            modes = a.ASSIST_MODES
            mode = st.radio("Assistance", modes, index=modes.index(w["settings"]["assist_mode"]), disabled=locked, key=f"am_{w['lab_id']}_{w['settings']['assist_mode']}",
                            help="Guided: start from worked examples. Fading: help reduces as you succeed. Independent: references only after your own attempt." + (" Locked for this lab." if locked else ""))
            if mode != w["settings"]["assist_mode"]:
                a.set_assist_mode(w, mode)
                save()
                st.rerun()
            for n in S.get("_notes", []):
                st.caption("\u2139\uFE0F " + n)
            with st.expander("Reset this lab"):
                st.caption("Deletes ONLY this lab's workspace. Other labs are unaffected.")
                sure = st.checkbox("I want to delete this lab's work", key=f"rs_{w['lab_id']}")
                if st.button("Reset lab", disabled=not sure, key=f"rsb_{w['lab_id']}"):
                    tm()["workspaces"].pop(w["lab_id"], None)
                    m.ensure_workspace(tm(), w["lab_id"])
                    tm()["current_step"] = 1
                    save()
                    st.rerun()
            st.caption("Progress saves automatically. Keep the URL (it holds your session id) to resume.")
        if st.button("\U0001F3E0 Home", use_container_width=True):
            tm()["selected_lab"] = None
            save()
            st.rerun()


sidebar()
if not tm()["selected_lab"]:
    home()
    st.stop()

w = ws()
cfg = WORKSHOPS[w["lab_id"]]
st.markdown(f"<h1 style='margin-bottom:0'>{cfg['name']}</h1>", unsafe_allow_html=True)
st.caption(f"{tm_labs.profile(w['lab_id'])['role']} \u00b7 {cfg['level']} \u00b7 {cfg['duration']}")
tracker(w)
step = tm()["current_step"] if tm()["current_step"] in PAGES else 0
PAGES[step]()
