"""
Code Orbit Security Toolkit - AI-Powered Security Suite
Complete 4 Tasks in 1 Professional Dashboard
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import os

# ========== PAGE CONFIGURATION ==========
st.set_page_config(
    page_title="Code Orbit Security Toolkit",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Import Modules
from modules.ai_password_analyzer import AIPasswordAnalyzer
from modules.cipher_suite import CipherSuite
from modules.phishing_detector_ai import PhishingDetectorAI
from modules.advanced_scanner import AdvancedScanner
from modules.report_engine import ReportEngine

# Initialize
password_analyzer = AIPasswordAnalyzer()
phishing_detector = PhishingDetectorAI()
report_engine = ReportEngine()

# ========== CUSTOM CSS - BRIGHTER THEME ==========
st.markdown("""
<style>
    /* ========== GLOBAL ========== */
    .stApp {
        background: linear-gradient(135deg, #f0f4f8 0%, #e2e8f0 50%, #f0f4f8 100%);
    }
    
    /* ========== HEADER ========== */
    .main-header {
        font-size: 2.8rem;
        font-weight: 700;
        background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 50%, #6d28d9 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        margin-bottom: 0.2rem;
    }
    
    .sub-header {
        font-size: 1.1rem;
        color: #475569;
        margin-top: -0.5rem;
        margin-bottom: 1.5rem;
    }
    
    /* ========== METRIC CARDS ========== */
    .metric-card {
        background: #ffffff;
        padding: 1.5rem;
        border-radius: 16px;
        border: 1px solid #e2e8f0;
        text-align: center;
        transition: all 0.3s ease;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05), 0 2px 4px -1px rgba(0, 0, 0, 0.03);
    }
    
    .metric-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
        border-color: #4f46e5;
    }
    
    .metric-value {
        font-size: 2.5rem;
        font-weight: 700;
        color: #1e293b;
    }
    
    .metric-label {
        color: #64748b;
        font-size: 0.9rem;
        margin-top: 0.5rem;
    }
    
    .metric-icon {
        font-size: 2rem;
        margin-bottom: 0.5rem;
    }
    
    /* ========== BUTTONS ========== */
    .stButton > button {
        background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%);
        color: white;
        border: none;
        font-weight: 600;
        border-radius: 8px;
        padding: 0.6rem 1.5rem;
        transition: all 0.3s ease;
        box-shadow: 0 4px 6px -1px rgba(79, 70, 229, 0.2);
    }
    
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 10px 15px -3px rgba(79, 70, 229, 0.3);
    }
    
    .stButton > button:active {
        transform: translateY(0px);
    }
    
    /* ========== SIDEBAR ========== */
    .css-1d391kg {
        background: linear-gradient(180deg, #ffffff 0%, #f8fafc 100%);
        border-right: 1px solid #e2e8f0;
    }
    
    .css-1d391kg .stRadio label {
        color: #475569;
        font-weight: 500;
        padding: 0.5rem 0.75rem;
        border-radius: 8px;
        transition: all 0.2s ease;
    }
    
    .css-1d391kg .stRadio label:hover {
        background: rgba(79, 70, 229, 0.05);
        color: #1e293b;
    }
    
    .css-1d391kg .stRadio [aria-checked="true"] + div {
        background: rgba(79, 70, 229, 0.1);
        color: #4f46e5;
        border-left: 3px solid #4f46e5;
    }
    
    /* ========== EXPANDER ========== */
    .streamlit-expanderHeader {
        background-color: #ffffff !important;
        border-radius: 8px !important;
        border: 1px solid #e2e8f0 !important;
        color: #1e293b !important;
        font-weight: 600 !important;
    }
    
    .streamlit-expanderHeader:hover {
        border-color: #4f46e5 !important;
    }
    
    .streamlit-expanderContent {
        background: #f8fafc !important;
        border-radius: 0 0 8px 8px !important;
        padding: 1rem !important;
    }
    
    /* ========== TABS ========== */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background: #f1f5f9;
        border-radius: 12px;
        padding: 4px;
    }
    
    .stTabs [data-baseweb="tab"] {
        background: transparent;
        border-radius: 8px;
        padding: 0.5rem 1.5rem;
        border: none;
        color: #64748b;
        font-weight: 500;
        transition: all 0.2s ease;
    }
    
    .stTabs [data-baseweb="tab"]:hover {
        color: #1e293b;
        background: rgba(79, 70, 229, 0.05);
    }
    
    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%) !important;
        color: #ffffff !important;
        box-shadow: 0 4px 6px -1px rgba(79, 70, 229, 0.2);
    }
    
    /* ========== INPUT FIELDS ========== */
    .stTextInput input {
        background: #ffffff !important;
        border: 1px solid #e2e8f0 !important;
        color: #1e293b !important;
        border-radius: 8px !important;
        padding: 0.6rem 1rem !important;
        transition: all 0.2s ease;
    }
    
    .stTextInput input:focus {
        border-color: #4f46e5 !important;
        box-shadow: 0 0 0 3px rgba(79, 70, 229, 0.15) !important;
    }
    
    .stTextInput input::placeholder {
        color: #94a3b8 !important;
    }
    
    .stTextArea textarea {
        background: #ffffff !important;
        border: 1px solid #e2e8f0 !important;
        color: #1e293b !important;
        border-radius: 8px !important;
        padding: 0.6rem 1rem !important;
        transition: all 0.2s ease;
    }
    
    .stTextArea textarea:focus {
        border-color: #4f46e5 !important;
        box-shadow: 0 0 0 3px rgba(79, 70, 229, 0.15) !important;
    }
    
    /* ========== SELECT BOX ========== */
    .stSelectbox select {
        background: #ffffff !important;
        border: 1px solid #e2e8f0 !important;
        border-radius: 8px !important;
        color: #1e293b !important;
    }
    
    /* ========== SLIDER ========== */
    .stSlider .stSliderValue {
        background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%) !important;
    }
    
    /* ========== METRIC STYLES ========== */
    [data-testid="stMetric"] {
        background: #ffffff;
        border-radius: 12px;
        padding: 1rem 1.5rem;
        border: 1px solid #e2e8f0;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
    }
    
    [data-testid="stMetric"]:hover {
        border-color: #4f46e5;
    }
    
    [data-testid="stMetric"] label {
        color: #475569 !important;
        font-weight: 500 !important;
    }
    
    [data-testid="stMetric"] .stMetricValue {
        color: #1e293b !important;
        font-weight: 700 !important;
    }
    
    /* ========== CODE BLOCK ========== */
    .stCodeBlock {
        background: #1e293b !important;
        border-radius: 8px !important;
        border: 1px solid #e2e8f0 !important;
    }
    
    .stCodeBlock pre {
        color: #f1f5f9 !important;
    }
    
    /* ========== ALERTS ========== */
    .stAlert {
        border-radius: 10px !important;
        border: 1px solid !important;
    }
    
    .stAlert-info {
        background: #eff6ff !important;
        border-color: #3b82f6 !important;
        color: #1e3a5f !important;
    }
    
    .stAlert-success {
        background: #ecfdf5 !important;
        border-color: #22c55e !important;
        color: #064e3b !important;
    }
    
    .stAlert-warning {
        background: #fffbeb !important;
        border-color: #f59e0b !important;
        color: #78350f !important;
    }
    
    .stAlert-error {
        background: #fef2f2 !important;
        border-color: #ef4444 !important;
        color: #991b1b !important;
    }
    
    /* ========== FOOTER ========== */
    .footer {
        text-align: center;
        color: #94a3b8;
        padding: 2rem 0;
        border-top: 1px solid #e2e8f0;
        margin-top: 2rem;
        font-size: 0.9rem;
    }
    
    /* ========== EDUCATION CENTER ========== */
    .education-bg {
        background: linear-gradient(135deg, #eff6ff 0%, #e0e7ff 50%, #ede9fe 100%);
        padding: 2rem;
        border-radius: 16px;
        border: 1px solid #c7d2fe;
        margin-bottom: 1.5rem;
        position: relative;
        overflow: hidden;
    }
    
    .education-card {
        background: rgba(255, 255, 255, 0.85);
        backdrop-filter: blur(10px);
        padding: 1.5rem;
        border-radius: 12px;
        border: 1px solid #e2e8f0;
        transition: all 0.3s ease;
        margin-bottom: 0.5rem;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
    }
    
    .education-card:hover {
        transform: translateY(-3px);
        border-color: #4f46e5;
        box-shadow: 0 10px 15px -3px rgba(79, 70, 229, 0.1);
    }
    
    .education-title {
        text-align: center;
        padding: 0.5rem;
    }
    
    .education-title h1 {
        color: #1e293b !important;
    }
    
    .education-title p {
        color: #475569 !important;
    }
    
    /* ========== RESPONSIVE ========== */
    @media (max-width: 768px) {
        .main-header {
            font-size: 2rem;
        }
        
        .metric-value {
            font-size: 2rem;
        }
        
        .metric-card {
            padding: 1rem;
        }
    }
    
    @media (max-width: 480px) {
        .main-header {
            font-size: 1.5rem;
        }
        
        .metric-value {
            font-size: 1.5rem;
        }
        
        .sub-header {
            font-size: 0.9rem;
        }
    }
</style>
""", unsafe_allow_html=True)

# ========== SIDEBAR ==========
with st.sidebar:
    # Try to display logo if exists
    logo_displayed = False
    
    # Try shield_icon.png first
    if os.path.exists("images/shield_icon.png"):
        st.image("images/shield_icon.png", width=80)
        logo_displayed = True
    elif os.path.exists("images/favicon.ico"):
        st.image("images/favicon.ico", width=80)
        logo_displayed = True
    elif os.path.exists("static/logo.svg"):
        st.image("static/logo.svg", width=80)
        logo_displayed = True
    elif os.path.exists("images/logo.svg"):
        st.image("images/logo.svg", width=80)
        logo_displayed = True
    
    if not logo_displayed:
        st.markdown("# 🛡️")
    
    st.markdown("## 🛡️ Code Orbit Security Toolkit")
    st.caption("v3.0.0 | AI-Powered")
    st.markdown("---")
    
    page = st.radio(
        "📌 Navigation",
        [
            "🏠 Command Center",
            "🔐 Password Vault",
            "🔑 Crypto Toolkit",
            "🎣 Phishing Detector",
            "🌐 Network Scanner",
            "📊 Reports",
            "📚 Education"
        ],
        index=0
    )
    
    st.markdown("---")
    st.caption("🔒 All data processed locally")
    st.caption(f"🕐 {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    st.caption("👤 Code Orbit Tech Intern")

# ========== COMMAND CENTER ==========
if page == "🏠 Command Center":
    if os.path.exists("images/banner.png"):
        st.image("images/banner.png", use_column_width=True)
    
    st.markdown('<p class="main-header">🛡️ Code Orbit Security Toolkit</p>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">AI-Powered Cybersecurity Suite</p>', unsafe_allow_html=True)
    st.markdown("---")
    
    st.subheader("🖼️ Core Cybersecurity Concepts")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if os.path.exists("images/network_icon.png"):
            st.image("images/network_icon.png", width=100)
        st.caption("🌐 Network Security")
        st.write("Secure data flow and infrastructure monitoring.")
    
    with col2:
        if os.path.exists("images/phishing_icon.png"):
            st.image("images/phishing_icon.png", width=100)
        st.caption("🎣 Phishing Attacks")
        st.write("Deceptive emails with 'verify account' prompts.")
    
    with col3:
        if os.path.exists("images/password_icon.png"):
            st.image("images/password_icon.png", width=100)
        st.caption("🔐 Strong Passwords")
        st.write("12+ characters with uppercase, lowercase, numbers, and symbols.")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if os.path.exists("images/biometric_icon.png"):
            st.image("images/biometric_icon.png", width=100)
        st.caption("👆 Biometric Protection")
        st.write("Fingerprint and PIN authentication for privacy.")
    
    with col2:
        if os.path.exists("images/vuln_icon.png"):
            st.image("images/vuln_icon.png", width=100)
        st.caption("🔍 Vulnerability Scanner")
        st.write("Tools like Nmap and Wireshark to find vulnerabilities.")
    
    with col3:
        if os.path.exists("images/shield_icon.png"):
            st.image("images/shield_icon.png", width=100)
        st.caption("🛡️ Digital Shield")
        st.write("Data protection, encryption, and secure connections.")
    
    st.markdown("---")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown("""
        <div class="metric-card">
            <div class="metric-icon">🛡️</div>
            <div class="metric-value">98%</div>
            <div class="metric-label">Security Score</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="metric-card">
            <div class="metric-icon">🔐</div>
            <div class="metric-value">156</div>
            <div class="metric-label">Passwords Analyzed</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class="metric-card">
            <div class="metric-icon">🎣</div>
            <div class="metric-value">23</div>
            <div class="metric-label">Phishing Detected</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown("""
        <div class="metric-card">
            <div class="metric-icon">📊</div>
            <div class="metric-value">12</div>
            <div class="metric-label">Reports Generated</div>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📈 Security Trends")
        months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun']
        scores = [75, 82, 78, 85, 92, 98]
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=months,
            y=scores,
            mode='lines+markers',
            name='Security Score',
            line=dict(color='#4f46e5', width=3),
            marker=dict(size=10, color='#7c3aed')
        ))
        fig.update_layout(
            template='plotly_white',
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            height=300,
            margin=dict(l=0, r=0, t=0, b=0),
            xaxis=dict(showgrid=False),
            yaxis=dict(showgrid=True, gridcolor='#e2e8f0', range=[0, 100])
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("🎯 Tool Usage")
        fig = go.Figure(data=[go.Pie(
            labels=['Password', 'Cipher', 'Phishing', 'Network'],
            values=[35, 20, 30, 15],
            hole=.4,
            marker=dict(colors=['#4f46e5', '#7c3aed', '#a78bfa', '#c4b5fd'])
        )])
        fig.update_layout(
            template='plotly_white',
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            height=300,
            margin=dict(l=0, r=0, t=0, b=0)
        )
        st.plotly_chart(fig, use_container_width=True)
    
    st.subheader("⚡ Quick Actions")
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        if st.button("🔐 Check Password", use_container_width=True):
            st.info("Navigate to Password Vault")
    with col2:
        if st.button("🎣 Scan Email", use_container_width=True):
            st.info("Navigate to Phishing Detector")
    with col3:
        if st.button("🌐 Scan Network", use_container_width=True):
            st.info("Navigate to Network Scanner")
    with col4:
        if st.button("📊 Generate Report", use_container_width=True):
            st.info("Navigate to Reports")

# ========== PASSWORD VAULT ==========
elif page == "🔐 Password Vault":
    col1, col2 = st.columns([1, 4])
    with col1:
        if os.path.exists("images/password_icon.png"):
            st.image("images/password_icon.png", width=64)
    with col2:
        st.markdown('<p class="main-header">🔐 Password Vault</p>', unsafe_allow_html=True)
        st.markdown('<p class="sub-header">AI-Powered Password Analysis & Management</p>', unsafe_allow_html=True)
    st.markdown("---")
    
    tab1, tab2 = st.tabs(["🔍 Analyze Password", "🔄 Generate Password"])
    
    with tab1:
        col1, col2 = st.columns([3, 1])
        
        with col1:
            password = st.text_input("Enter password to analyze:", type="password", placeholder="Type your password...")
            
            if st.button("🔍 Analyze", type="primary") and password:
                with st.spinner("Analyzing with AI..."):
                    result = password_analyzer.analyze(password)
                
                col_a, col_b, col_c, col_d = st.columns(4)
                col_a.metric("Strength", result['strength'])
                col_b.metric("Score", f"{result['score']}/100")
                col_c.metric("Entropy", f"{result['entropy']} bits")
                col_d.metric("Crack Time", result['crack_time'])
                
                st.info(f"🤖 AI Confidence: {result['ai_confidence']} | Breach Status: {result['breach_status']}")
                
                with st.expander("📋 Detailed Feedback", expanded=True):
                    for msg in result['feedback']:
                        if "🌟" in msg or "✅" in msg:
                            st.success(msg)
                        elif "🟡" in msg:
                            st.warning(msg)
                        else:
                            st.error(msg)
                
                with st.expander("💡 Improvement Suggestions"):
                    for suggestion in result['suggestions']:
                        st.write(f"💡 {suggestion}")
        
        with col2:
            st.info("""
            ### 💡 Password Tips
            - 🔐 12+ characters
            - 🔠 Upper + Lowercase
            - 🔢 Include numbers
            - ✨ Special characters
            - 🚫 Avoid common words
            - 🔄 Use passphrases
            """)
    
    with tab2:
        st.subheader("🔐 Generate Strong Password")
        col1, col2 = st.columns(2)
        
        with col1:
            length = st.slider("Password Length", 8, 32, 16)
            include_special = st.checkbox("Include Special Characters", value=True)
        
        with col2:
            if st.button("🎲 Generate", type="primary"):
                result = password_analyzer.generate_password(length, include_special)
                password = result['password']
                
                st.code(password, language="text")
                st.caption(f"Length: {len(password)} characters | Strength: {result['analysis']['strength']}")
                
                with st.expander("📊 Analysis of Generated Password"):
                    analysis = result['analysis']
                    st.write(f"**Score:** {analysis['score']}/100")
                    st.write(f"**Entropy:** {analysis['entropy']} bits")
                    st.write(f"**Crack Time:** {analysis['crack_time']}")
                    st.write(f"**Breach Status:** {analysis['breach_status']}")

# ========== CRYPTO TOOLKIT ==========
elif page == "🔑 Crypto Toolkit":
    col1, col2 = st.columns([1, 4])
    with col1:
        if os.path.exists("images/cipher_icon.png"):
            st.image("images/cipher_icon.png", width=64)
    with col2:
        st.markdown('<p class="main-header">🔑 Crypto Toolkit</p>', unsafe_allow_html=True)
        st.markdown('<p class="sub-header">Caesar Cipher Encryption & Analysis</p>', unsafe_allow_html=True)
    st.markdown("---")
    
    mode = st.radio("Select Mode:", ["🔒 Encrypt", "🔓 Decrypt", "💥 Brute Force"], horizontal=True)
    text = st.text_area("📝 Input Text:", placeholder="Enter your text here...", height=100)
    
    if mode != "💥 Brute Force":
        shift = st.slider("Shift Value (1-25)", 1, 25, 3)
        
        if st.button("▶️ Process", type="primary") and text:
            if "Encrypt" in mode:
                result = CipherSuite.encrypt(text, shift)
                st.success(f"**Encrypted Text:** {result['text']}")
            else:
                result = CipherSuite.decrypt(text, shift)
                st.success(f"**Decrypted Text:** {result['text']}")
            
            with st.expander("🔬 Educational Analysis"):
                analysis = CipherSuite.analyze_cipher(text, shift, mode)
                st.write(f"**Algorithm:** {analysis['algorithm']}")
                st.write(f"**Security Level:** {analysis['security_level']}")
                st.write(f"**Explanation:** {analysis['explanation']}")
                st.write(f"**History:** {analysis['history']}")
                st.info(f"💡 {analysis['vulnerability']}")
    
    else:
        if st.button("💥 Crack Cipher", type="primary") and text:
            results = CipherSuite.brute_force(text)
            st.subheader("🔎 All Possible Decryptions")
            
            sorted_results = sorted(results.items(), key=lambda x: x[1]['confidence'], reverse=True)
            
            for shift, data in sorted_results[:3]:
                st.success(f"**Shift {shift}** (Confidence: {data['confidence']}%): {data['text']}")
            
            with st.expander("Show All Shifts"):
                for shift, data in sorted_results[3:]:
                    st.write(f"**Shift {shift}:** {data['text']}")

# ========== PHISHING DETECTOR ==========
elif page == "🎣 Phishing Detector":
    col1, col2 = st.columns([1, 4])
    with col1:
        if os.path.exists("images/phishing_icon.png"):
            st.image("images/phishing_icon.png", width=64)
    with col2:
        st.markdown('<p class="main-header">🎣 Phishing Detector</p>', unsafe_allow_html=True)
        st.markdown('<p class="sub-header">AI-Powered Email Threat Analysis</p>', unsafe_allow_html=True)
    st.markdown("---")
    
    tab1, tab2 = st.tabs(["🔍 Analyze Email", "📝 Samples"])
    
    with tab1:
        email = st.text_area("📧 Paste email content here:", height=250)
        
        if st.button("🔍 Analyze", type="primary") and email:
            with st.spinner("Analyzing with AI..."):
                result = phishing_detector.analyze(email)
            
            col1, col2, col3 = st.columns(3)
            col1.metric("Risk Level", result['risk'])
            col2.metric("Score", f"{result['score']}/100")
            col3.metric("AI Confidence", result['ai_confidence'])
            
            with st.expander("🚨 Red Flags Detected", expanded=True):
                if result['flags']:
                    for flag in result['flags']:
                        st.error(flag)
                else:
                    st.success("✅ No red flags detected!")
            
            with st.expander("💡 Recommendations"):
                for rec in result['recommendations']:
                    st.write(f"• {rec}")
    
    with tab2:
        st.subheader("📝 Sample Phishing Emails")
        st.caption("Learn to identify phishing attempts with these real-world examples")
        
        samples = phishing_detector.generate_sample_emails()
        for i, sample in enumerate(samples):
            with st.expander(f"📧 Sample {i+1}: {sample['subject']}"):
                st.write(sample['body'])
                st.warning(f"🎯 Risk Level: {sample['risk']}")
                st.error("🚨 " + ", ".join(sample['flags']))

# ========== NETWORK SCANNER ==========
elif page == "🌐 Network Scanner":
    col1, col2 = st.columns([1, 4])
    with col1:
        if os.path.exists("images/network_icon.png"):
            st.image("images/network_icon.png", width=64)
    with col2:
        st.markdown('<p class="main-header">🌐 Network Scanner</p>', unsafe_allow_html=True)
        st.markdown('<p class="sub-header">Advanced Port Scanning with CVE Mapping</p>', unsafe_allow_html=True)
    st.markdown("---")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        target = st.text_input("🎯 Target IP Address:", value="127.0.0.1")
    
    with col2:
        port_range = st.slider("📊 Port Range:", 1, 1024, (1, 100))
    
    if st.button("🚀 Start Scan", type="primary") and target:
        with st.spinner(f"Scanning {target} ports {port_range[0]}-{port_range[1]}..."):
            scanner = AdvancedScanner(target)
            results = scanner.scan(start=port_range[0], end=port_range[1])
        
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Open Ports", results['open_count'])
        col2.metric("Vulnerabilities", results['vulnerability_count'])
        col3.metric("Security Score", f"{results['security_score']}/100")
        col4.metric("Risk Level", results['risk_level'])
        
        if results['open_ports']:
            st.subheader("🔍 Scan Results")
            data = []
            for port in results['open_ports']:
                data.append({
                    "Port": port['port'],
                    "Service": port['service'],
                    "Vulnerabilities": len(port['vulnerabilities']),
                    "Risk Score": port['risk_score']
                })
            df = pd.DataFrame(data)
            st.dataframe(df, use_container_width=True)
            
            if results['vulnerability_count'] > 0:
                st.subheader("🚨 Vulnerabilities Found")
                for port in results['open_ports']:
                    for vuln in port['vulnerabilities']:
                        st.warning(f"🔴 **{vuln['id']}** - {vuln['description']} (Port {port['port']})")
            
            with st.expander("💡 Security Recommendations"):
                for rec in results['recommendations']:
                    st.write(f"• {rec}")
        else:
            st.info("✅ No open ports found in the given range")

# ========== REPORTS ==========
elif page == "📊 Reports":
    st.markdown('<p class="main-header">📊 Security Reports</p>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">Generate Professional Security Reports</p>', unsafe_allow_html=True)
    st.markdown("---")
    
    st.info("📊 Generate comprehensive security reports for all tools")
    
    report_type = st.selectbox(
        "Select Report Type",
        ["Complete Security Assessment", "Password Analysis Report", "Phishing Detection Report", "Network Scan Report"]
    )
    
    if st.button("📥 Generate Report", type="primary"):
        with st.spinner("Generating professional report..."):
            data = {
                'summary': {
                    'Security Score': '98%',
                    'Passwords Analyzed': '156',
                    'Phishing Detected': '23',
                    'Open Ports': '5',
                    'Vulnerabilities Fixed': '12'
                },
                'vulnerabilities': [
                    {'type': 'Weak Password', 'severity': 'Medium', 'description': 'User passwords need improvement'},
                    {'type': 'Open Port', 'severity': 'High', 'description': 'Port 3389 open - RDP vulnerability'},
                    {'type': 'Phishing Attempt', 'severity': 'High', 'description': 'Suspicious email detected'}
                ],
                'recommendations': [
                    'Enable 2FA for all accounts',
                    'Close unnecessary open ports',
                    'Implement email filtering',
                    'Regular password updates',
                    'Conduct security awareness training'
                ]
            }
            filename = report_engine.generate_security_report(data, "Security_Assessment")
            st.success(f"✅ Report generated successfully!")
            
            with open(filename, 'rb') as f:
                st.download_button(
                    "📥 Download PDF Report",
                    f.read(),
                    file_name="security_assessment_report.pdf",
                    mime="application/pdf"
                )

# ========== EDUCATION ==========
elif page == "📚 Education":
    st.markdown("""
    <div class="education-bg">
        <div class="education-title">
            <h1 style="font-size: 2.8rem; margin-bottom: 0.2rem;">📚 Education Center</h1>
            <p style="font-size: 1.1rem;">Learn Cybersecurity Fundamentals</p>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    st.subheader("🖼️ Core Cybersecurity Concepts")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown('<div class="education-card">', unsafe_allow_html=True)
        if os.path.exists("images/network_icon.png"):
            st.image("images/network_icon.png", width=80)
        st.markdown("**🌐 Global Network Security**")
        st.write("Interconnected network devices ensuring secure data flow and infrastructure monitoring.")
        st.markdown('</div>', unsafe_allow_html=True)
        
        st.markdown('<div class="education-card">', unsafe_allow_html=True)
        if os.path.exists("images/phishing_icon.png"):
            st.image("images/phishing_icon.png", width=80)
        st.markdown("**🎣 Phishing Attacks**")
        st.write("Deceptive emails using 'verify account' prompts to create panic and prompt quick actions.")
        st.markdown('</div>', unsafe_allow_html=True)
        
        st.markdown('<div class="education-card">', unsafe_allow_html=True)
        if os.path.exists("images/password_icon.png"):
            st.image("images/password_icon.png", width=80)
        st.markdown("**🔐 Strong Passwords**")
        st.write("Robust credentials should include uppercase/lowercase letters, numbers, symbols, and be 12+ characters.")
        st.markdown('</div>', unsafe_allow_html=True)
        
        st.markdown('<div class="education-card">', unsafe_allow_html=True)
        if os.path.exists("images/biometric_icon.png"):
            st.image("images/biometric_icon.png", width=80)
        st.markdown("**👆 Biometric Protection**")
        st.write("Biometric authentication for locking sensitive apps with fingerprints or PINs for privacy.")
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col2:
        st.markdown('<div class="education-card">', unsafe_allow_html=True)
        if os.path.exists("images/vuln_icon.png"):
            st.image("images/vuln_icon.png", width=80)
        st.markdown("**🔍 Vulnerability Scanner**")
        st.write("Scanning/defense applications using network tools like Nmap and Wireshark to find and fix vulnerabilities.")
        st.markdown('</div>', unsafe_allow_html=True)
        
        st.markdown('<div class="education-card">', unsafe_allow_html=True)
        if os.path.exists("images/shield_icon.png"):
            st.image("images/shield_icon.png", width=80)
        st.markdown("**🛡️ Digital Shield**")
        st.write("Cyber defense iconography indicating data protection, encryption, or secure connections.")
        st.markdown('</div>', unsafe_allow_html=True)
    
    st.markdown("---")
    
    st.subheader("🛠️ Practical Actions for Better Security")
    
    st.success("✅ **Protect your accounts:** Enable Two-Factor Authentication (2FA) for a crucial extra layer of security")
    st.success("✅ **Secure sensitive data:** Use reputable password managers (with AES local encryption) for complex passwords")
    st.success("✅ **Check for leaks:** Regularly use 'Have I Been Pwned' to check if your email is in a data breach")
    st.success("✅ **Use trusted tools:** Rely on well-known tools like Nmap or Burp Suite, not obscure 'hack' tools")

# ========== FOOTER ==========
st.markdown("""
<div class="footer">
    🛡️ Code Orbit Security Toolkit v3.0.0<br>
    Developed by Pradheepa. M | Code Orbit Tech Internship<br>
    🔒 All data is processed locally | Built with Streamlit
</div>
""", unsafe_allow_html=True)