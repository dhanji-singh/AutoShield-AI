import os

import streamlit as st
from scanner_ui import scanner_page


API_BASE = os.getenv("API_BASE", "http://backend:8000").rstrip("/")

st.set_page_config(
    page_title="AutoShield AI • Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Only trusted, static interface markup is rendered as HTML.
# Request evidence and model output retain their plain-text renderers.
st.markdown("""
<style>
:root{--as-bg:#090b10;--as-panel:#11151d;--as-red:#f34242;--as-gold:#f5c56c;--as-text:#f1f0ed;--as-muted:#a0a7b5;--as-line:#292e39}
.stApp{background:radial-gradient(ellipse at 96% 0%,#41151d66,transparent 36%),var(--as-bg);color:var(--as-text);font-family:'Segoe UI',sans-serif;color-scheme:dark}
[data-testid="stHeader"]{background:#090b10de;border-bottom:1px solid #ffffff08}
[data-testid="stMainBlockContainer"]{max-width:1600px;padding:2.2rem 3rem 3rem}
[data-testid="stSidebar"]{background:#0d1016;border-right:1px solid var(--as-line)}
[data-testid="stSidebarContent"]{padding-top:1rem}
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p{color:var(--as-muted)}
[data-testid="stSidebar"] [role="radiogroup"]{gap:8px}
[data-testid="stSidebar"] [role="radiogroup"] label{padding:13px 14px!important;border:1px solid transparent;border-radius:7px;transition:background .2s,border .2s;width:100%;margin:0}
[data-testid="stSidebar"] [role="radiogroup"] label:hover{background:#ffffff06;border-color:#363b47}
[data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked){background:linear-gradient(90deg,#a825303b,#f3424206);border-color:#f3424255;box-shadow:inset 3px 0 var(--as-red)}
[data-testid="stSidebar"] [role="radiogroup"] label p{font-size:14px!important;letter-spacing:.3px;color:#e7e9ee!important}
[data-testid="stSidebar"] [role="radiogroup"] label>div:first-child{display:none}
[data-testid="stSidebar"] [role="radiogroup"] label:focus-within{outline:2px solid var(--as-gold);outline-offset:2px}
.as-brand{display:flex;align-items:center;gap:12px;padding:6px 0 28px}
.as-mark{background:var(--as-red);color:white;font-size:27px;font-weight:950;width:42px;height:47px;display:grid;place-items:center;clip-path:polygon(0 0,100% 0,100% 75%,50% 100%,0 75%)}
.as-brand strong{font-size:21px;letter-spacing:-1px}.as-brand small{display:block;font:9px/2 monospace;letter-spacing:3px;color:#8e96a6}
.as-kicker{font:10px/1.6 monospace;letter-spacing:2.5px;color:#9199aa;margin:5px 0 14px}
.as-sidecard{margin-top:28px;padding:18px;border:1px solid #f5c56c30;border-radius:8px;background:linear-gradient(145deg,#29201655,#15171e);font-size:13px;color:#b9bdc7;line-height:1.7}
.as-sidecard strong{color:var(--as-gold);font:11px monospace;letter-spacing:1.5px;display:block;margin-bottom:9px}
.as-topline{display:flex;justify-content:space-between;align-items:center;gap:20px;margin:0 0 26px;font:10px/1.6 monospace;letter-spacing:2px;color:#969eaf}
.as-topline b{color:#f1f0ed;font-weight:500}.as-tag{padding:6px 10px;border:1px solid #f5c56c45;color:var(--as-gold);border-radius:4px;white-space:nowrap}
.as-hero{position:relative;overflow:hidden;min-height:300px;display:flex;align-items:center;justify-content:space-between;padding:38px 42px;background:linear-gradient(110deg,#171923 10%,#21131d 65%,#471722);border:1px solid #63303b;border-radius:12px;isolation:isolate;margin-bottom:24px}
.as-hero::before{content:'';position:absolute;inset:0;z-index:-1;background-image:radial-gradient(#ffffff19 .8px,transparent .8px);background-size:7px 7px;mask-image:linear-gradient(90deg,transparent,#000);opacity:.55}
.as-hero::after{content:'';position:absolute;right:28%;top:-70%;height:240%;width:2px;background:#f3424235;transform:rotate(28deg);box-shadow:24px 0 #f3424214,160px 0 #f3424214;z-index:-1}
.as-hero-copy{max-width:640px;z-index:1}.as-eyebrow{font:10px monospace;letter-spacing:2px;color:#f5c56c;margin-bottom:22px;display:flex;align-items:center;gap:9px}
.as-eyebrow::before{content:'';width:20px;height:2px;background:var(--as-red)}
.as-hero h1{font-family:Impact,'Arial Narrow',sans-serif!important;font-weight:900!important;font-size:clamp(40px,4.5vw,76px)!important;line-height:1.02!important;letter-spacing:.2px!important;margin:0!important;padding:0!important;color:#f3f0eb!important;text-transform:uppercase}
.as-hero h1 span{color:#ff565c}.as-hero p{font-size:14px;color:#b5afbb;line-height:1.7;max-width:460px;margin:20px 0 0}
.as-reactor{width:230px;height:230px;position:relative;display:grid;place-items:center;flex-shrink:0;margin:0 12px 0 32px;filter:drop-shadow(0 0 20px #ed344025)}
.as-ring{position:absolute;inset:0;border:1px solid #ff777738;border-radius:50%}
.as-ring.one{border:3px dashed #f3424277;animation:as-spin 55s linear infinite;inset:4px}
.as-ring.two{inset:20px;border:1px solid #f5c56c99;outline:6px solid #f5c56c08;outline-offset:5px}
.as-ring.three{inset:39px;border:9px solid #ff4a5526;border-top-color:#ff5a65;border-bottom-color:#f5c56c;animation:as-spin 18s linear infinite reverse}
.as-core{width:116px;height:126px;display:grid;place-items:center;background:linear-gradient(150deg,#fa5d64,#8e1c29);clip-path:polygon(0 0,100% 0,100% 65%,50% 100%,0 65%);color:#fff2df;font:italic 84px Impact,sans-serif;text-shadow:0 3px 10px #300;animation:as-glow 5s ease-in-out infinite}
.as-reactor-label{position:absolute;bottom:-12px;font:8px monospace;letter-spacing:3px;color:#d19b9f;background:#27131b;padding:5px 10px}
.as-strip{display:flex;gap:0;border:1px solid var(--as-line);border-radius:8px;background:#10131a;margin-bottom:26px;overflow:hidden}
.as-strip div{flex:1;padding:15px 20px;font:10px/1.8 monospace;color:#979ead;letter-spacing:1px;border-right:1px solid var(--as-line)}
.as-strip div:last-child{border:0}.as-strip b{display:block;font:600 12px 'Segoe UI',sans-serif;letter-spacing:.2px;color:#dedfe7;margin-top:2px}.as-strip em{font-style:normal;color:var(--as-red);margin-right:7px}
h2,h3{color:#f1f0ed!important;font-weight:750!important;letter-spacing:-.6px}h3{font-size:23px!important}
[data-testid="stCaptionContainer"]{color:var(--as-muted)!important}
[data-testid="stMetric"]{position:relative;padding:22px 23px;background:linear-gradient(130deg,#191c26,#10131a);border:1px solid #34323d;border-radius:10px;overflow:hidden;transition:border-color .2s,transform .2s}
[data-testid="stMetric"]::before{content:'';position:absolute;top:0;left:22px;width:30px;height:3px;background:var(--as-red)}
[data-testid="stMetric"]:hover{border-color:#ba444d;transform:translateY(-3px)}
[data-testid="stMetricLabel"]{color:#a7adbc!important;font-size:12px}
[data-testid="stMetricValue"]{color:#faf3e5!important;font-family:'Arial Narrow','Segoe UI',sans-serif!important;font-weight:700;font-size:38px!important;letter-spacing:-1.5px}
[data-testid="stDataFrame"]{border:1px solid var(--as-line);border-radius:9px;overflow:hidden}
[data-testid="stTextInput"] input{background:#121720!important;color:#f0f0f5!important}
[data-testid="stTextInput"]>div,[data-baseweb="select"]>div{background:#121720!important;border-color:#343948!important;border-radius:7px!important;color:#f0f0f5!important}
[data-baseweb="popover"]{color-scheme:dark}
[data-testid="stWidgetLabel"] p{color:#c6cbd7!important;font-size:13px}
[data-testid="stButton"] button,[data-testid="stLinkButton"] a{border-radius:6px!important;border:1px solid #44404a!important;background:#181b25!important;color:#edeef4!important;transition:transform .2s,box-shadow .2s!important;min-height:42px;font-weight:650!important}
[data-testid="stButton"] button:hover,[data-testid="stLinkButton"] a:hover{transform:translateY(-2px);border-color:#f34242!important;box-shadow:0 5px 22px #ed34401c}
[data-testid="stButton"] button[kind="primary"]{background:linear-gradient(115deg,#ed3444,#b51e30)!important;border-color:#fa5965!important;box-shadow:0 4px 20px #d1273325}
[data-testid="stExpander"]{background:#12151d;border:1px solid var(--as-line)!important;border-radius:8px!important}
[data-testid="stCode"]{border:1px solid var(--as-line);border-radius:7px}
[data-testid="stAlert"]{border-radius:7px;border:1px solid #ffffff0d}
[data-testid="stText"]{line-height:1.8;color:#d5d9e2}
hr{border-color:#292c37!important;margin:1.8rem 0!important}
.as-traffic-bar{height:8px;display:flex;gap:3px;overflow:hidden;border-radius:5px;background:#252a35;margin:22px 0 10px}.as-traffic-bar span{height:100%;min-width:0;transition:width .5s ease}
.as-legend{display:flex;flex-wrap:wrap;gap:18px;font:10px monospace;color:#a5adbc;margin-bottom:22px}.as-legend i{width:6px;height:6px;display:inline-block;margin-right:7px;border-radius:2px}
.as-footer{display:flex;justify-content:space-between;gap:15px;border-top:1px solid #282d38;margin-top:35px;padding-top:18px;font:9px/1.8 monospace;letter-spacing:1.8px;color:#717b8e}
@keyframes as-spin{to{transform:rotate(360deg)}}@keyframes as-glow{50%{filter:brightness(1.2)}}
@media(max-width:1100px){[data-testid="stMainBlockContainer"]{padding:2rem 1.5rem}.as-hero{padding:30px}.as-reactor{width:175px;height:175px}.as-core{width:85px;height:95px;font-size:60px}.as-ring.three{inset:30px}}
@media(max-width:700px){[data-testid="stMainBlockContainer"]{padding:1.5rem 1rem}.as-topline{font-size:8px;letter-spacing:1px}.as-hero{padding:26px 23px;min-height:260px}.as-hero h1{font-size:46px!important}.as-reactor{position:absolute;right:-90px;opacity:.2;width:240px;height:240px;z-index:-1}.as-hero p{max-width:290px}.as-strip{flex-wrap:wrap}.as-strip div{flex-basis:45%;padding:12px;font-size:9px}.as-footer{flex-direction:column}[data-testid="stMetricValue"]{font-size:30px!important}}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important;scroll-behavior:auto!important}}
</style>
""", unsafe_allow_html=True)

# Scanner is the sole workspace; legacy WAF pages are no longer rendered.
with st.sidebar:
    st.markdown('<div class="as-brand"><div class="as-mark">A</div><div><strong>AUTOSHIELD AI</strong><small>WEB SECURITY SCANNER</small></div></div>', unsafe_allow_html=True)
    st.markdown('### Scanner')
    st.caption('Scan a target, inspect evidence and compare saved results.')
    st.divider()
    st.markdown('**Your workflow**')
    st.caption('1. Configure a scan\n\n2. Review findings and evidence\n\n3. Generate an AI review\n\n4. Compare scans and export reports')
    st.divider()
    st.caption('Scan history refreshes every 3 seconds. AI runs when requested or when enabled for a new scan.')

st.markdown('<div class="as-topline"><span>AUTOSHIELD AI / <b>SCANNER</b></span><span class="as-tag">WEB SECURITY ASSESSMENT</span></div>', unsafe_allow_html=True)
st.title('Web security scanner')
st.caption('Scan your target. Understand the evidence. Track changes over time.')
scanner_page(API_BASE)
st.markdown('<div class="as-footer"><span>AUTOSHIELD AI / WEB SECURITY SCANNER</span><span>FINDINGS · EVIDENCE · AI REVIEW · REPORTS</span></div>', unsafe_allow_html=True)
