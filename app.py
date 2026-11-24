"""
PASSGUARD AI - Cybersecurity Password Strength Checker & Defense Suite
Professional SaaS Theme: Callback-Driven State Architecture, Zero Emojis, No Widget Instantiation Errors
"""

import streamlit as st
from analyzer import analyze_password, AnalysisResult
from generator import generate_password, generate_passphrase

# Page Configuration
st.set_page_config(
    page_title="PassGuard AI | Password Strength Checker",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom SaaS Light Theme CSS
CUSTOM_CSS = """
<style>
    /* 1. Remove Streamlit Default Header, Toolbar, and Footer */
    header[data-testid="stHeader"],
    div[data-testid="stToolbar"],
    #MainMenu,
    footer {
        display: none !important;
        visibility: hidden !important;
        height: 0 !important;
    }

    /* Viewport Padding */
    .main .block-container {
        padding-top: 1.5rem !important;
        padding-bottom: 2.5rem !important;
        max-width: 1200px !important;
    }
    [data-testid="stSidebarContent"] {
        padding-top: 1.5rem !important;
        padding-left: 1rem !important;
        padding-right: 1rem !important;
    }

    /* 2. Color Palette & Typography */
    .stApp {
        background-color: #F8FAFC !important;
        color: #0F172A !important;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif !important;
    }

    h1, h2, h3, h4, h5, h6 {
        color: #0F172A !important;
        font-weight: 700 !important;
        letter-spacing: -0.01em !important;
    }

    p, span, div {
        color: #0F172A;
    }

    /* Form Labels & Captions */
    label,
    label[data-testid="stWidgetLabel"],
    label[data-testid="stWidgetLabel"] p,
    label p,
    .stSlider label,
    .stSelectbox label,
    .stRadio label,
    .stCheckbox label {
        color: #0F172A !important;
        font-weight: 600 !important;
        font-size: 0.9rem !important;
    }

    .stCaption,
    [data-testid="stCaptionContainer"],
    [data-testid="stCaptionContainer"] p {
        color: #475569 !important;
        font-size: 0.85rem !important;
    }

    /* 3. Sidebar (Dark Navy: #0B192C) */
    [data-testid="stSidebar"] {
        background-color: #0B192C !important;
        border-right: 1px solid #1E293B !important;
    }
    [data-testid="stSidebar"] * {
        color: #F1F5F9;
    }
    [data-testid="stSidebar"] p {
        color: #94A3B8 !important;
    }

    /* Sidebar Buttons (High-contrast slate with white text) */
    [data-testid="stSidebar"] .stButton > button,
    [data-testid="stSidebar"] button {
        background-color: #1E293B !important;
        color: #F8FAFC !important;
        border: 1px solid #334155 !important;
        border-radius: 8px !important;
        font-weight: 600 !important;
        font-size: 0.85rem !important;
        padding: 6px 12px !important;
        transition: all 0.15s ease !important;
    }
    [data-testid="stSidebar"] .stButton > button:hover,
    [data-testid="stSidebar"] button:hover {
        background-color: #0284C7 !important;
        border-color: #0284C7 !important;
        color: #FFFFFF !important;
    }

    /* Sidebar Navigation Radios */
    [data-testid="stSidebar"] div[role="radiogroup"] {
        gap: 6px !important;
    }
    [data-testid="stSidebar"] div[role="radiogroup"] label {
        background-color: transparent !important;
        border-radius: 8px !important;
        padding: 8px 12px !important;
        margin-bottom: 2px !important;
        transition: all 0.15s ease !important;
    }
    [data-testid="stSidebar"] div[role="radiogroup"] label:hover {
        background-color: #1E293B !important;
    }
    [data-testid="stSidebar"] div[role="radiogroup"] label[data-checked="true"],
    [data-testid="stSidebar"] div[role="radiogroup"] label:has(input:checked) {
        background-color: #0284C7 !important;
    }
    [data-testid="stSidebar"] div[role="radiogroup"] label[data-checked="true"] p,
    [data-testid="stSidebar"] div[role="radiogroup"] label:has(input:checked) p {
        color: #FFFFFF !important;
        font-weight: 700 !important;
    }

    /* 4. White Card Containers (#FFFFFF with #E2E8F0 border) */
    div[data-testid="stVerticalBlockBorderWrapper"] {
        background-color: #FFFFFF !important;
        border: 1px solid #E2E8F0 !important;
        border-radius: 12px !important;
        box-shadow: 0 1px 3px rgba(15, 23, 42, 0.04) !important;
        padding: 18px 22px !important;
        margin-bottom: 12px !important;
    }

    /* 5. All Main Buttons (Consistent Height, Rounded Corners, Sky Blue Theme) */
    .main .stButton > button,
    .main button {
        border-radius: 8px !important;
        font-weight: 600 !important;
        font-size: 0.92rem !important;
        min-height: 42px !important;
        transition: all 0.15s ease !important;
    }

    /* Primary Buttons (#0284C7 Sky Blue) */
    .main .stButton > button[kind="primary"],
    .main button[data-testid="baseButton-primary"],
    .main button[data-testid="stBaseButton-primary"] {
        background-color: #0284C7 !important;
        border: 1px solid #0284C7 !important;
        color: #FFFFFF !important;
        box-shadow: 0 1px 2px rgba(2, 132, 199, 0.2) !important;
    }
    .main .stButton > button[kind="primary"]:hover,
    .main button[data-testid="baseButton-primary"]:hover,
    .main button[data-testid="stBaseButton-primary"]:hover {
        background-color: #0369A1 !important;
        border-color: #0369A1 !important;
        color: #FFFFFF !important;
    }
    .main .stButton > button[kind="primary"] *,
    .main button[data-testid="baseButton-primary"] *,
    .main button[data-testid="stBaseButton-primary"] * {
        color: #FFFFFF !important;
    }

    /* Secondary Buttons (Light with Sky Blue Hover) */
    .main .stButton > button[kind="secondary"],
    .main button[data-testid="baseButton-secondary"],
    .main button[data-testid="stBaseButton-secondary"] {
        background-color: #FFFFFF !important;
        border: 1px solid #CBD5E1 !important;
        color: #0F172A !important;
    }
    .main .stButton > button[kind="secondary"]:hover,
    .main button[data-testid="baseButton-secondary"]:hover,
    .main button[data-testid="stBaseButton-secondary"]:hover {
        background-color: #F0F9FF !important;
        border-color: #0284C7 !important;
        color: #0284C7 !important;
    }

    /* 6. Form Inputs (Text Input, Selectbox) */
    div[data-baseweb="input"],
    div[data-baseweb="base-input"] {
        background-color: #FFFFFF !important;
        border: 1px solid #CBD5E1 !important;
        border-radius: 8px !important;
        transition: border-color 0.15s ease, box-shadow 0.15s ease !important;
    }
    div[data-baseweb="input"]:focus-within,
    div[data-baseweb="base-input"]:focus-within {
        border-color: #0284C7 !important;
        box-shadow: 0 0 0 3px rgba(2, 132, 199, 0.15) !important;
    }
    div[data-baseweb="input"] input,
    div[data-baseweb="base-input"] input {
        background-color: #FFFFFF !important;
        color: #0F172A !important;
        font-size: 0.95rem !important;
    }
    div[data-baseweb="input"] input::placeholder {
        color: #94A3B8 !important;
    }

    /* Selectbox dropdowns */
    div[data-testid="stSelectbox"] div[data-baseweb="select"] {
        background-color: #FFFFFF !important;
        border: 1px solid #CBD5E1 !important;
        border-radius: 8px !important;
    }
    div[data-testid="stSelectbox"] div[data-baseweb="select"]:focus-within {
        border-color: #0284C7 !important;
        box-shadow: 0 0 0 3px rgba(2, 132, 199, 0.15) !important;
    }
    div[data-testid="stSelectbox"] div[data-baseweb="select"] * {
        background-color: #FFFFFF !important;
        color: #0F172A !important;
    }
    div[data-baseweb="popover"],
    div[data-baseweb="menu"],
    ul[role="listbox"] {
        background-color: #FFFFFF !important;
        border: 1px solid #E2E8F0 !important;
        border-radius: 8px !important;
        box-shadow: 0 4px 12px rgba(15, 23, 42, 0.08) !important;
    }
    li[role="option"] {
        color: #0F172A !important;
        background-color: #FFFFFF !important;
    }
    li[role="option"]:hover,
    li[role="option"][aria-selected="true"] {
        background-color: #E0F2FE !important;
        color: #0284C7 !important;
    }

    /* 7. Checkboxes & Radio Buttons */
    div[data-testid="stCheckbox"] label span:first-child {
        border-color: #CBD5E1 !important;
        background-color: #FFFFFF !important;
        border-radius: 4px !important;
    }
    div[data-testid="stCheckbox"] label:hover span:first-child {
        border-color: #0284C7 !important;
    }
    div[data-testid="stCheckbox"] input:checked + div,
    div[data-testid="stCheckbox"] label:has(input:checked) span:first-child {
        background-color: #0284C7 !important;
        border-color: #0284C7 !important;
        color: #FFFFFF !important;
    }
    div[data-testid="stCheckbox"] label p {
        color: #0F172A !important;
        font-size: 0.9rem !important;
        font-weight: 500 !important;
    }

    /* Radio buttons in Main Page */
    .main div[data-testid="stRadio"] div[role="radiogroup"] {
        gap: 12px !important;
    }
    .main div[data-testid="stRadio"] label {
        color: #0F172A !important;
        font-size: 0.9rem !important;
        font-weight: 500 !important;
    }
    .main div[data-testid="stRadio"] input:checked + div,
    .main div[data-testid="stRadio"] label:has(input:checked) > div:first-child {
        border-color: #0284C7 !important;
    }
    .main div[data-testid="stRadio"] label:has(input:checked) > div:first-child > div {
        background-color: #0284C7 !important;
    }

    /* 8. Slider Controls */
    div[data-testid="stSlider"] div[data-baseweb="slider"] > div:first-child {
        background: #E2E8F0 !important;
    }
    div[data-testid="stSlider"] div[data-baseweb="slider"] > div:first-child > div {
        background: #0284C7 !important;
    }
    div[data-testid="stSlider"] div[role="slider"] {
        background-color: #0284C7 !important;
        border: 2px solid #FFFFFF !important;
        box-shadow: 0 1px 3px rgba(2, 132, 199, 0.4) !important;
    }
    div[data-testid="stSlider"] div[data-testid="stSliderTickBar"] {
        color: #64748B !important;
    }
    div[data-testid="stSlider"] div[data-testid="stSliderThumbValue"] {
        color: #0284C7 !important;
        font-weight: 700 !important;
    }

    /* 9. Code Box & Sky Blue Copy Button */
    div[data-testid="stCode"] {
        background-color: #F8FAFC !important;
        border: 1px solid #CBD5E1 !important;
        border-radius: 8px !important;
        padding: 8px 12px !important;
    }
    div[data-testid="stCode"] pre {
        background-color: transparent !important;
        margin: 0 !important;
        padding: 2px 0 !important;
    }
    div[data-testid="stCode"] code {
        background-color: transparent !important;
        color: #0F172A !important;
        font-family: 'JetBrains Mono', Consolas, Monaco, monospace !important;
        font-size: 1.1rem !important;
        font-weight: 700 !important;
        letter-spacing: 0.04em !important;
    }
    div[data-testid="stCode"] button,
    button[data-testid="stCodeCopyButton"] {
        background-color: #E0F2FE !important;
        border: 1px solid #BAE6FD !important;
        border-radius: 6px !important;
        color: #0284C7 !important;
        padding: 6px !important;
        transition: all 0.15s ease !important;
    }
    div[data-testid="stCode"] button:hover,
    button[data-testid="stCodeCopyButton"]:hover {
        background-color: #0284C7 !important;
        border-color: #0284C7 !important;
        color: #FFFFFF !important;
    }
    div[data-testid="stCode"] button svg,
    button[data-testid="stCodeCopyButton"] svg {
        stroke: #0284C7 !important;
    }
    div[data-testid="stCode"] button:hover svg,
    button[data-testid="stCodeCopyButton"]:hover svg {
        stroke: #FFFFFF !important;
    }

    /* 10. Metric Display */
    div[data-testid="stMetric"] {
        background-color: #F8FAFC !important;
        border: 1px solid #E2E8F0 !important;
        border-radius: 8px !important;
        padding: 10px 14px !important;
    }
    div[data-testid="stMetricLabel"],
    div[data-testid="stMetricLabel"] * {
        color: #475569 !important;
        font-size: 0.85rem !important;
        font-weight: 600 !important;
    }
    div[data-testid="stMetricValue"],
    div[data-testid="stMetricValue"] * {
        color: #0F172A !important;
        font-size: 1.45rem !important;
        font-weight: 800 !important;
    }
    div[data-testid="stMetricDelta"],
    div[data-testid="stMetricDelta"] * {
        font-weight: 700 !important;
        font-size: 0.88rem !important;
    }

    /* 11. Metric Badges */
    .metric-badge {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background: #F1F5F9;
        border: 1px solid #E2E8F0;
        padding: 4px 10px;
        border-radius: 6px;
        font-size: 0.82rem;
        color: #334155;
        font-weight: 600;
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# ==============================================================================
# SESSION STATE INITIALIZATION
# ==============================================================================
if "input_password_field" not in st.session_state:
    st.session_state["input_password_field"] = ""
if "gen_password" not in st.session_state:
    st.session_state["gen_password"] = generate_password(length=14)
if "nav_choice" not in st.session_state:
    st.session_state["nav_choice"] = "Password Analyzer"

# ==============================================================================
# STREAMLIT CALLBACK FUNCTIONS (Safe Pre-Execution State Updates)
# ==============================================================================
def set_weak_sample():
    st.session_state["input_password_field"] = "password123"
    st.session_state["nav_choice"] = "Password Analyzer"

def set_strong_sample():
    st.session_state["input_password_field"] = "K7#qP9!mZ2@vL4"
    st.session_state["nav_choice"] = "Password Analyzer"

def set_patterned_sample():
    st.session_state["input_password_field"] = "qwerty2024abc"
    st.session_state["nav_choice"] = "Password Analyzer"

def generate_quick_password():
    st.session_state["gen_password"] = generate_password(length=14)

def send_generated_to_analyzer():
    st.session_state["input_password_field"] = st.session_state.get("gen_password", "")
    st.session_state["nav_choice"] = "Password Analyzer"

def generate_character_password():
    st.session_state["gen_password"] = generate_password(
        length=st.session_state.get("slider_length", 16),
        use_upper=st.session_state.get("check_upper", True),
        use_lower=st.session_state.get("check_lower", True),
        use_digits=st.session_state.get("check_digits", True),
        use_symbols=st.session_state.get("check_symbols", True),
        exclude_ambiguous=st.session_state.get("check_ambig", False)
    )

def generate_passphrase_callback():
    st.session_state["gen_password"] = generate_passphrase(
        num_words=st.session_state.get("slider_words", 4),
        separator=st.session_state.get("select_sep", "-"),
        capitalize=st.session_state.get("check_cap", True),
        include_number=st.session_state.get("check_num", True)
    )

# Circular SVG Gauge Generator
def render_circular_gauge(score: int, color: str) -> str:
    circumference = 251.3
    offset = circumference - (score / 100.0) * circumference
    return f"""
    <div style="display: flex; justify-content: center; align-items: center; width: 92px; height: 92px; margin: auto;">
        <svg width="88" height="88" viewBox="0 0 100 100">
            <circle cx="50" cy="50" r="40" fill="none" stroke="#F1F5F9" stroke-width="8" />
            <circle cx="50" cy="50" r="40" fill="none" stroke="{color}" stroke-width="8"
                    stroke-dasharray="{circumference}" stroke-dashoffset="{offset}"
                    stroke-linecap="round" transform="rotate(-90 50 50)" />
            <text x="50" y="47" text-anchor="middle" font-family="-apple-system, sans-serif" font-size="22" font-weight="800" fill="#0F172A">{score}</text>
            <text x="50" y="64" text-anchor="middle" font-family="-apple-system, sans-serif" font-size="11" font-weight="600" fill="#64748B">/ 100</text>
        </svg>
    </div>
    """

# ==============================================================================
# SIDEBAR
# ==============================================================================
with st.sidebar:
    st.markdown("""
    <div style="text-align: center; padding: 10px 0 14px 0;">
        <div style="display: inline-flex; align-items: center; justify-content: center; width: 44px; height: 44px; background: rgba(2, 132, 199, 0.15); border: 2px solid #0284C7; border-radius: 10px; margin-bottom: 8px;">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#38BDF8" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
        </div>
        <div style="font-size: 1.25rem; font-weight: 800; color: #FFFFFF; margin: 0;">PassGuard <span style="color: #38BDF8;">AI</span></div>
        <div style="font-size: 0.75rem; color: #94A3B8; margin-top: 2px;">Check. Strengthen. Stay Secure.</div>
    </div>
    """, unsafe_allow_html=True)

    nav_choice = st.radio(
        "Navigation",
        options=["Password Analyzer", "Password Generator", "About"],
        key="nav_choice",
        label_visibility="collapsed"
    )

    st.markdown("<div style='border-top: 1px solid #1E293B; margin: 14px 0;'></div>", unsafe_allow_html=True)
    st.markdown("<div style='font-size: 0.75rem; font-weight: 700; color: #94A3B8; letter-spacing: 0.05em; margin-bottom: 8px;'>QUICK SAMPLES</div>", unsafe_allow_html=True)

    sample_col1, sample_col2 = st.columns(2)
    with sample_col1:
        st.button("Weak", use_container_width=True, on_click=set_weak_sample)
    with sample_col2:
        st.button("Strong", use_container_width=True, on_click=set_strong_sample)

    st.button("Patterned", use_container_width=True, on_click=set_patterned_sample)

    st.markdown("""
    <div style="background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 10px; padding: 12px; text-align: center; margin-top: 24px;">
        <div style="display: flex; justify-content: center; margin-bottom: 4px;">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#38BDF8" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
            </svg>
        </div>
        <div style="font-weight: 700; font-size: 0.85rem; color: #FFFFFF; margin-bottom: 2px;">Your Privacy First</div>
        <div style="font-size: 0.72rem; color: #94A3B8; line-height: 1.4;">No data is stored.<br>100% local analysis.</div>
    </div>
    """, unsafe_allow_html=True)

# ==============================================================================
# MAIN PAGE ROUTING
# ==============================================================================

if nav_choice == "Password Analyzer":
    # --------------------------------------------------------------------------
    # HEADER BANNER (Clean inline Lucide SVGs, no emojis)
    # --------------------------------------------------------------------------
    st.markdown("""
    <div style="display: flex; justify-content: space-between; align-items: center; padding-bottom: 12px; margin-bottom: 16px; border-bottom: 1px solid #E2E8F0; flex-wrap: wrap; gap: 12px;">
        <div style="display: flex; align-items: center; gap: 12px;">
            <div style="display: flex; align-items: center; justify-content: center; width: 44px; height: 44px; background: #E0F2FE; border: 2px solid #BAE6FD; border-radius: 10px; color: #0284C7;">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#0284C7" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
            </div>
            <div>
                <div style="font-size: 1.65rem; font-weight: 800; color: #0F172A; line-height: 1.2;">
                    Password Strength <span style="color: #0284C7;">Checker</span>
                </div>
                <div style="color: #64748B; font-size: 0.9rem; margin-top: 2px;">
                    Analyze your password and get security insights.
                </div>
            </div>
        </div>
        <div style="display: inline-flex; align-items: center; gap: 6px; font-size: 0.82rem; font-weight: 600; color: #0F172A; background: #F1F5F9; padding: 6px 12px; border-radius: 20px; border: 1px solid #E2E8F0;">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#0F172A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
            </svg>
            Secure Your Digital Life
        </div>
    </div>
    """, unsafe_allow_html=True)

    # --------------------------------------------------------------------------
    # CARD 1: PASSWORD INPUT
    # --------------------------------------------------------------------------
    with st.container(border=True):
        col_label, col_show = st.columns([4, 2], vertical_alignment="center")
        with col_label:
            st.markdown("<div style='font-size: 0.95rem; font-weight: 700; color: #0F172A;'>Enter password</div>", unsafe_allow_html=True)
        with col_show:
            show_password = st.checkbox("Show password characters", value=False)

        col_inp, col_btn = st.columns([5, 1], vertical_alignment="center")
        with col_inp:
            input_type = "default" if show_password else "password"
            user_password = st.text_input(
                "Enter password",
                type=input_type,
                placeholder="Type or paste a password...",
                key="input_password_field",
                label_visibility="collapsed"
            )
        with col_btn:
            check_clicked = st.button("Check", type="primary", use_container_width=True)

    # Perform Security Analysis
    result: AnalysisResult = analyze_password(user_password)

    # Perform Security Analysis
    result: AnalysisResult = analyze_password(user_password)

    # ----------------------------------------------------------------------
    # CARD 2: STRENGTH METER & SCORE
    # ----------------------------------------------------------------------
    if user_password:
        if result.strength_level == "Very Strong":
            feedback_subtitle = "Your password is well protected and exceeds modern defense thresholds!"
            gauge_color = "#0284C7"
        elif result.strength_level == "Strong":
            feedback_subtitle = "Solid password defense! Good resistance against automated attacks."
            gauge_color = "#0EA5E9"
        elif result.strength_level == "Good":
            feedback_subtitle = "Reasonable security baseline, but can be hardened with more entropy."
            gauge_color = "#38BDF8"
        elif result.strength_level == "Fair":
            feedback_subtitle = "Vulnerable to hybrid dictionary and credential-stuffing attacks."
            gauge_color = "#F59E0B"
        else:
            feedback_subtitle = "Critically weak! Vulnerable to immediate brute force or dictionary lookup."
            gauge_color = "#EF4444"

        svg_gauge = render_circular_gauge(result.score, gauge_color)
        meter_title = result.strength_level
        progress_val = result.score / 100.0
    else:
        feedback_subtitle = "Type a password above or click 'Generate Password' to evaluate security."
        gauge_color = "#94A3B8"
        svg_gauge = render_circular_gauge(0, gauge_color)
        meter_title = "Awaiting Input"
        progress_val = 0.0

    with st.container(border=True):
        col_gauge, col_info = st.columns([1, 5], vertical_alignment="center")
        with col_gauge:
            st.markdown(svg_gauge, unsafe_allow_html=True)
        with col_info:
            st.markdown(f"<div style='font-size: 1.7rem; font-weight: 800; color: {gauge_color}; margin-bottom: 2px;'>{meter_title}</div>", unsafe_allow_html=True)
            st.markdown(f"<div style='color: #64748B; font-size: 0.95rem; margin-bottom: 10px;'>{feedback_subtitle}</div>", unsafe_allow_html=True)
            st.progress(progress_val)

    # ----------------------------------------------------------------------
    # ROW 3: TWO-COLUMN DETAILS
    # ----------------------------------------------------------------------
    col_analysis_left, col_generator_right = st.columns([1, 1], gap="medium")

    # LEFT COLUMN: SECURITY ANALYSIS
    with col_analysis_left:
        with st.container(border=True):
            st.markdown("""
            <div style="display: flex; align-items: center; gap: 8px; font-size: 1.1rem; font-weight: 700; color: #0F172A; margin-bottom: 12px;">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#0284C7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
                Security Analysis
            </div>
            """, unsafe_allow_html=True)

            if user_password:
                checklist_items = [
                    (f"Length: {result.length} characters", result.length >= 8),
                    ("Uppercase letters", result.has_upper),
                    ("Lowercase letters", result.has_lower),
                    ("Numbers", result.has_digits),
                    ("Special characters", result.has_symbols),
                    ("No breached wordlist match", not result.is_common),
                ]

                pass_svg = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#10B981" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="margin-right: 8px; flex-shrink: 0;"><path d="M20 6 9 17l-5-5"/></svg>'
                fail_svg = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#EF4444" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="margin-right: 8px; flex-shrink: 0;"><path d="M18 6 6 18M6 6l12 12"/></svg>'

                for label, passed in checklist_items:
                    icon = pass_svg if passed else fail_svg
                    text_color = "#1E293B" if passed else "#64748B"
                    st.markdown(f"<div style='display: flex; align-items: center; font-size: 0.92rem; margin-bottom: 8px; color: {text_color};'>{icon} {label}</div>", unsafe_allow_html=True)

                st.markdown("<div style='border-top: 1px solid #F1F5F9; margin: 12px 0;'></div>", unsafe_allow_html=True)

                # Tip / Alert Box (clean SVG icon, no emojis)
                if not result.vulnerabilities and result.score >= 80:
                    st.markdown("""
                    <div style="background-color: #ECFDF5; border: 1px solid #A7F3D0; border-radius: 8px; padding: 12px 14px; color: #065F46; font-size: 0.88rem; display: flex; gap: 8px; align-items: flex-start;">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#10B981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink: 0; margin-top: 1px;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                        <div><strong>Tip:</strong> Password satisfies recommended complexity and entropy thresholds.</div>
                    </div>
                    """, unsafe_allow_html=True)
                elif result.is_common:
                    st.markdown("""
                    <div style="background-color: #FEF2F2; border: 1px solid #FECACA; border-radius: 8px; padding: 12px 14px; color: #991B1B; font-size: 0.88rem; display: flex; gap: 8px; align-items: flex-start;">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#EF4444" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink: 0; margin-top: 1px;"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                        <div><strong>Critical Warning:</strong> This password appears in common breached wordlists. Change it immediately.</div>
                    </div>
                    """, unsafe_allow_html=True)
                elif result.vulnerabilities:
                    top_v = result.vulnerabilities[0]
                    st.markdown(f"""
                    <div style="background-color: #FFFBEB; border: 1px solid #FDE68A; border-radius: 8px; padding: 12px 14px; color: #92400E; font-size: 0.88rem; display: flex; gap: 8px; align-items: flex-start;">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#F59E0B" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink: 0; margin-top: 1px;"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                        <div><strong>Tip ({top_v.severity} Risk):</strong> {top_v.description}<br><strong>Recommendation:</strong> {top_v.suggestion}</div>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown("""
                    <div style="background-color: #F0F9FF; border: 1px solid #BAE6FD; border-radius: 8px; padding: 12px 14px; color: #0369A1; font-size: 0.88rem; display: flex; gap: 8px; align-items: flex-start;">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#0284C7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink: 0; margin-top: 1px;"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>
                        <div><strong>Tip:</strong> Add a diverse mix of letters, numbers, and symbols to achieve maximum defense.</div>
                    </div>
                    """, unsafe_allow_html=True)

                st.markdown(f"""
                <div style="margin-top: 14px; display: flex; gap: 8px; flex-wrap: wrap;">
                    <span class="metric-badge">Entropy: <strong>{result.entropy_bits} bits</strong></span>
                    <span class="metric-badge">Pool: <strong>{result.pool_size}</strong></span>
                    <span class="metric-badge">Offline Crack: <strong>{result.estimated_crack_time_offline}*</strong></span>
                </div>
                """, unsafe_allow_html=True)

                with st.expander("Scoring Breakdown & Crack Time Heuristics", expanded=False):
                    st.caption("Point calculations (0-100 scale):")
                    for item, points in result.score_breakdown.items():
                        sign = "+" if points > 0 else ""
                        st.write(f"- **{item}**: `{sign}{points} pts`")
                    if result.is_common:
                        st.caption("Score capped to 15 because password was detected in common breached wordlists.")
                    st.caption(
                        "* Crack-time estimations are purely illustrative theoretical calculations based on brute-force combinatorics and standard computational benchmarks. They do not constitute a guarantee of real-world security."
                    )
            else:
                # Neutral baseline checklist when awaiting input
                neutral_svg = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#94A3B8" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="margin-right: 8px; flex-shrink: 0;"><circle cx="12" cy="12" r="9"/></svg>'
                default_items = [
                    "Length: Minimum 8 characters",
                    "Uppercase letters (A-Z)",
                    "Lowercase letters (a-z)",
                    "Numbers (0-9)",
                    "Special characters (!@#$)",
                    "No breached wordlist match",
                ]
                for item in default_items:
                    st.markdown(f"<div style='display: flex; align-items: center; font-size: 0.92rem; margin-bottom: 8px; color: #64748B;'>{neutral_svg} {item}</div>", unsafe_allow_html=True)

                st.markdown("<div style='border-top: 1px solid #F1F5F9; margin: 12px 0;'></div>", unsafe_allow_html=True)
                st.markdown("""
                <div style="background-color: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 8px; padding: 12px 14px; color: #475569; font-size: 0.88rem; display: flex; gap: 8px; align-items: flex-start;">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#0284C7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink: 0; margin-top: 1px;"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>
                    <div><strong>Tip:</strong> Enter a password above or click 'Generate Password' to begin real-time cryptographic analysis.</div>
                </div>
                """, unsafe_allow_html=True)

                st.markdown("""
                <div style="margin-top: 14px; display: flex; gap: 8px; flex-wrap: wrap;">
                    <span class="metric-badge">Entropy: <strong>0 bits</strong></span>
                    <span class="metric-badge">Pool: <strong>0</strong></span>
                    <span class="metric-badge">Offline Crack: <strong>Instant*</strong></span>
                </div>
                """, unsafe_allow_html=True)

    # RIGHT COLUMN: PASSWORD GENERATOR QUICK CARD
    with col_generator_right:
        with st.container(border=True):
            st.markdown("""
            <div style="display: flex; align-items: center; gap: 8px; font-size: 1.1rem; font-weight: 700; color: #0F172A; margin-bottom: 4px;">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#0284C7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="m21 2-2 2m-6 6L3 20l-1 1 2 2 1-1 10-10m3-3 2-2m-9 9 3 3"/>
                </svg>
                Password Generator
            </div>
            """, unsafe_allow_html=True)
            st.caption("Generate a strong password for better security.")

            st.button("Generate Password", type="primary", use_container_width=True, on_click=generate_quick_password, key="btn_quick_gen")

            st.code(st.session_state.gen_password, language="text")

            col_c1, col_c2 = st.columns(2)
            with col_c1:
                st.button("Test in Analyzer", type="primary", use_container_width=True, on_click=send_generated_to_analyzer, key="btn_quick_test")
            with col_c2:
                st.caption("Uses Python secrets CSPRNG")

            st.markdown("""
            <div style="font-size: 0.82rem; color: #64748B; margin-top: 8px; display: flex; align-items: center; gap: 6px;">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#0284C7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>
                Use a mix of letters, numbers and symbols.
            </div>
            """, unsafe_allow_html=True)

elif nav_choice == "Password Generator":
    # --------------------------------------------------------------------------
    # FULL PASSWORD GENERATOR SUITE
    # --------------------------------------------------------------------------
    st.markdown("""
    <div style="display: flex; justify-content: space-between; align-items: center; padding-bottom: 12px; margin-bottom: 16px; border-bottom: 1px solid #E2E8F0; flex-wrap: wrap; gap: 12px;">
        <div style="display: flex; align-items: center; gap: 12px;">
            <div style="display: flex; align-items: center; justify-content: center; width: 44px; height: 44px; background: #E0F2FE; border: 2px solid #BAE6FD; border-radius: 10px; color: #0284C7;">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#0284C7" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                    <rect x="3" y="3" width="18" height="18" rx="2" ry="2"/>
                    <circle cx="8.5" cy="8.5" r="1.5" fill="#0284C7"/>
                    <circle cx="15.5" cy="15.5" r="1.5" fill="#0284C7"/>
                </svg>
            </div>
            <div>
                <div style="font-size: 1.65rem; font-weight: 800; color: #0F172A; line-height: 1.2;">
                    Password <span style="color: #0284C7;">Generator</span>
                </div>
                <div style="color: #64748B; font-size: 0.9rem; margin-top: 2px;">
                    Create high-entropy passwords using Python CSPRNG (secrets module).
                </div>
            </div>
        </div>
        <div style="display: inline-flex; align-items: center; gap: 6px; font-size: 0.82rem; font-weight: 600; color: #0F172A; background: #F1F5F9; padding: 6px 12px; border-radius: 20px; border: 1px solid #E2E8F0;">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#0F172A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            Cryptographically Secure
        </div>
    </div>
    """, unsafe_allow_html=True)

    col_gen_opt, col_gen_view = st.columns([1, 1], gap="medium")

    with col_gen_opt:
        with st.container(border=True):
            st.markdown("""
            <div style="display: flex; align-items: center; gap: 8px; font-size: 1.1rem; font-weight: 700; color: #0F172A; margin-bottom: 10px;">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#0284C7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <line x1="4" x2="4" y1="21" y2="14"/><line x1="4" x2="4" y1="10" y2="3"/><line x1="12" x2="12" y1="21" y2="12"/><line x1="12" x2="12" y1="8" y2="3"/><line x1="20" x2="20" y1="21" y2="16"/><line x1="20" x2="20" y1="12" y2="3"/>
                </svg>
                Generator Parameters
            </div>
            """, unsafe_allow_html=True)

            mode = st.radio("Generation Mode", ["Random Character String", "Memorable Passphrase"], horizontal=True, key="gen_mode_radio")

            if mode == "Random Character String":
                st.slider("Password Length", min_value=8, max_value=64, value=16, step=1, key="slider_length")
                c1, c2 = st.columns(2)
                with c1:
                    st.checkbox("Uppercase (A-Z)", value=True, key="check_upper")
                    st.checkbox("Lowercase (a-z)", value=True, key="check_lower")
                with c2:
                    st.checkbox("Digits (0-9)", value=True, key="check_digits")
                    st.checkbox("Symbols (!@#$)", value=True, key="check_symbols")

                st.checkbox("Exclude Ambiguous (1, l, I, 0, O)", value=False, key="check_ambig")

                st.button("Generate New Password", type="primary", use_container_width=True, on_click=generate_character_password, key="btn_full_gen")
            else:
                st.slider("Word Count", min_value=3, max_value=8, value=4, key="slider_words")
                st.selectbox("Word Separator", ["-", "_", ".", "#", " "], key="select_sep")
                st.checkbox("Capitalize Words", value=True, key="check_cap")
                st.checkbox("Append Number", value=True, key="check_num")

                st.button("Generate New Passphrase", type="primary", use_container_width=True, on_click=generate_passphrase_callback, key="btn_phrase_gen")

    with col_gen_view:
        with st.container(border=True):
            st.markdown("""
            <div style="display: flex; align-items: center; gap: 8px; font-size: 1.1rem; font-weight: 700; color: #0F172A; margin-bottom: 10px;">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#0284C7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="7.5" cy="15.5" r="4.5"/>
                    <path d="m21 3-9.5 9.5"/>
                    <path d="m15.5 7.5 3 3M18 5l3 3"/>
                </svg>
                Generated Credential
            </div>
            """, unsafe_allow_html=True)

            st.code(st.session_state.gen_password, language="text")

            col_act1, col_act2 = st.columns([1, 1], vertical_alignment="center")
            with col_act1:
                st.button("Send to Analyzer", type="primary", use_container_width=True, on_click=send_generated_to_analyzer, key="btn_send_analyzer_full")

            with col_act2:
                gen_audit = analyze_password(st.session_state.gen_password)
                st.metric("Defense Score", f"{gen_audit.score}/100", gen_audit.strength_level)

            st.markdown("<div style='border-top: 1px solid #E2E8F0; margin: 16px 0 12px 0;'></div>", unsafe_allow_html=True)
            st.markdown(f"""
            <div style="display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 12px;">
                <span class="metric-badge">Entropy: <strong>{gen_audit.entropy_bits} bits</strong></span>
                <span class="metric-badge">Pool: <strong>{gen_audit.pool_size} chars</strong></span>
                <span class="metric-badge">Offline Crack: <strong>{gen_audit.estimated_crack_time_offline}*</strong></span>
            </div>
            <div style="background-color: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 8px; padding: 12px; color: #475569; font-size: 0.85rem; display: flex; gap: 8px; align-items: flex-start;">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#0284C7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink: 0; margin-top: 2px;">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
                <div>
                    <strong>CSPRNG Guaranteed:</strong> Generated locally using Python <code>secrets</code> CSPRNG backed by OS kernel entropy. Unpredictable and safe against precomputed attacks.
                </div>
            </div>
            """, unsafe_allow_html=True)

else:
    # --------------------------------------------------------------------------
    # ABOUT & ARCHITECTURE
    # --------------------------------------------------------------------------
    st.markdown("""
    <div style="display: flex; justify-content: space-between; align-items: center; padding-bottom: 12px; margin-bottom: 16px; border-bottom: 1px solid #E2E8F0; flex-wrap: wrap; gap: 12px;">
        <div style="display: flex; align-items: center; gap: 12px;">
            <div style="display: flex; align-items: center; justify-content: center; width: 44px; height: 44px; background: #E0F2FE; border: 2px solid #BAE6FD; border-radius: 10px; color: #0284C7;">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#0284C7" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/>
                </svg>
            </div>
            <div>
                <div style="font-size: 1.65rem; font-weight: 800; color: #0F172A; line-height: 1.2;">
                    About <span style="color: #0284C7;">PassGuard AI</span>
                </div>
                <div style="color: #64748B; font-size: 0.9rem; margin-top: 2px;">
                    Architectural standards, information theory, and privacy model.
                </div>
            </div>
        </div>
        <div style="display: inline-flex; align-items: center; gap: 6px; font-size: 0.82rem; font-weight: 600; color: #0F172A; background: #F1F5F9; padding: 6px 12px; border-radius: 20px; border: 1px solid #E2E8F0;">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#0F172A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            Zero-Trust Architecture
        </div>
    </div>
    """, unsafe_allow_html=True)

    col_ab1, col_ab2 = st.columns(2, gap="medium")

    with col_ab1:
        with st.container(border=True):
            st.markdown("<div style='font-size: 1.1rem; font-weight: 700; color: #0F172A; margin-bottom: 8px;'>NIST SP 800-63B Standards</div>", unsafe_allow_html=True)
            st.markdown("""
            PASSGUARD AI is built according to modern NIST digital identity guidelines:
            - **Length Priority:** Exponential combinatorial resistance comes primarily from length (12-16+ characters).
            - **Breach Blacklisting:** Real-time cross-referencing against common breached wordlists.
            - **Pattern Neutralization:** Penalizes predictable keyboard walks and repeating characters that GPU tools exploit.
            """)

        with st.container(border=True):
            st.markdown("<div style='font-size: 1.1rem; font-weight: 700; color: #0F172A; margin-bottom: 8px;'>Shannon Entropy Modeling</div>", unsafe_allow_html=True)
            st.markdown("""
            Information entropy represents unpredictability in bits:
            $$H = L \\times \\log_2(R)$$
            PASSGUARD AI uses Shannon character frequency weighting to prevent misleadingly inflated entropy on repeated keystrokes (e.g. `aaaaaaaa`).
            """)

    with col_ab2:
        with st.container(border=True):
            st.markdown("<div style='font-size: 1.1rem; font-weight: 700; color: #0F172A; margin-bottom: 8px;'>100% Local Privacy Guarantee</div>", unsafe_allow_html=True)
            st.markdown("""
            - **No Network Transmission:** Zero telemetry, analytics, or external API calls.
            - **No Persistence:** Passwords are never saved, cached to disk, or logged.
            - **CSPRNG Randomness:** Powered by Python's `secrets` module backed by operating system entropy.
            """)

        with st.container(border=True):
            st.markdown("<div style='font-size: 1.1rem; font-weight: 700; color: #0F172A; margin-bottom: 8px;'>Tech Stack</div>", unsafe_allow_html=True)
            st.markdown("""
            - **Frontend / Framework:** Streamlit
            - **Heuristics:** Python Regex & Shannon entropy algorithms
            - **Randomness:** Python `secrets` CSPRNG
            - **Styling:** Custom minimal light SaaS theme
            """)

# Clean Footer
st.markdown("<div style='border-top: 1px solid #E2E8F0; margin-top: 24px; padding-top: 16px; text-align: center; color: #94A3B8; font-size: 0.8rem;'>PassGuard AI • Intelligent Cybersecurity Mini-Project • Developed for Ethical Defense & Security Education</div>", unsafe_allow_html=True)
