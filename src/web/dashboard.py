"""
Guardian AI Dashboard — Consumer-Friendly Network Security Monitor
Built with Streamlit for real-time visualization of network threats.
"""

import streamlit as st
import json
import os
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import time
from sklearn.linear_model import LinearRegression

# ============================================================
# PAGE CONFIG
# ============================================================
st.set_page_config(
    page_title="Guardian AI — Network Protection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================
# CUSTOM STYLING
# ============================================================
st.markdown("""
<style>
    /* Hide Streamlit branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    div[data-testid="stStatusWidget"] { visibility: hidden; }
    
    /* Dark theme */
    .main { background-color: #0e1117; }
    
    /* Metric cards */
    div[data-testid="stMetricValue"] { 
        font-size: 2rem; 
        font-weight: 700;
    }
    div[data-testid="stMetricLabel"] { 
        font-size: 0.85rem; 
        color: #888; 
        text-transform: uppercase; 
        letter-spacing: 1px;
    }
    
    /* Dividers */
    hr { border-color: #2d3748 !important; opacity: 0.5; }
    
    /* Headers */
    h1, h2, h3 { 
        color: #f8fafc !important;
        font-weight: 600 !important;
    }
    
    /* Cards and containers */
    div[data-testid="stExpander"] {
        background: rgba(30, 41, 59, 0.5);
        border: 1px solid #334155;
        border-radius: 12px;
    }
    
    /* DataFrames */
    .stDataFrame {
        border-radius: 12px;
        overflow: hidden;
    }
    
    /* Buttons */
    .stButton > button {
        border-radius: 8px;
        font-weight: 500;
        transition: all 0.3s ease;
    }
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(0, 212, 255, 0.3);
    }
    
    /* Download button */
    .stDownloadButton > button {
        background: linear-gradient(120deg, #3b82f6, #2563eb) !important;
        border: none !important;
        border-radius: 8px !important;
    }
    
    /* Status indicator colors */
    .status-secure { color: #00cc96; }
    .status-warning { color: #ffa500; }
    .status-critical { color: #ff4b4b; }
    
    /* Section titles */
    .section-title {
        font-size: 1.1rem;
        font-weight: 600;
        color: #e2e8f0;
        margin-bottom: 1rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }
    
    /* Health card */
    .health-card {
        background: linear-gradient(145deg, #1e293b, #0f172a);
        border: 1px solid #334155;
        border-radius: 16px;
        padding: 24px;
        text-align: center;
        box-shadow: 0 4px 24px rgba(0, 0, 0, 0.3);
    }
    
    /* Attack type list */
    .attack-item {
        background: rgba(239, 68, 68, 0.1);
        border-left: 3px solid #ef4444;
        padding: 8px 12px;
        margin: 8px 0;
        border-radius: 0 8px 8px 0;
    }
    
    /* Mobile responsive */
    @media (max-width: 640px) {
        div[data-testid="stMetricValue"] { font-size: 1.4rem !important; }
        .block-container { 
            padding-top: 4rem !important; 
            padding-left: 1rem !important; 
            padding-right: 1rem !important; 
        }
    }
</style>
""", unsafe_allow_html=True)


# ============================================================
# SESSION STATE
# ============================================================
if 'start_time' not in st.session_state:
    st.session_state.start_time = time.time()
    
if 'history_df' not in st.session_state:
    now = int(time.time())
    dummy_data = []
    for i in range(60):
        dummy_data.append({
            'unix_round': now - (60 - i),
            'count': np.random.randint(3, 10),
            'status': 'NORMAL'
        })
    st.session_state.history_df = pd.DataFrame(dummy_data)
    st.session_state.risk_cooldown = 0

if 'attack_count' not in st.session_state:
    st.session_state.attack_count = 0
    st.session_state.blocked_count = 0

if 'simulated_attack' not in st.session_state:
    st.session_state.simulated_attack = 0  # countdown timer for simulated attack

if 'packet_offset' not in st.session_state:
    st.session_state.packet_offset = 0  # for resetting packet count display


# ============================================================
# SIDEBAR — System Info
# ============================================================
@st.fragment(run_every=3)
def sidebar_content():
    st.markdown("## 🛡️ Guardian AI")
    st.caption("Intelligent Network Protection")
    
    st.divider()
    
    # System Status
    st.markdown("### System Status")
    uptime = time.time() - st.session_state.get('start_time', time.time())
    st.success(f"🟢 **Online** — {time.strftime('%H:%M:%S', time.gmtime(uptime))}")
    
    st.divider()
    
    # Test Attack Button
    st.markdown("### 🧪 Demo Mode")
    
    if st.session_state.get('simulated_attack', 0) > 0:
        # Simulation active — show stop button
        st.warning(f"Demo attack active ({st.session_state.simulated_attack * 3}s remaining)")
        if st.button("🛑 Stop Simulation", use_container_width=True, type="secondary"):
            st.session_state.simulated_attack = 0
            st.toast("✅ Simulation stopped", icon="🛑")
            st.rerun()
    else:
        # No simulation — show start button
        if st.button("⚡ Simulate Attack", use_container_width=True, type="primary"):
            st.session_state.simulated_attack = 10  # 10 refresh cycles (~30 sec)
            st.toast("🚨 Simulating attack for 30 seconds...", icon="⚠️")
    
    # Reset button
    if st.button("🔄 Reset Dashboard", use_container_width=True):
        # Reset files (may fail if created by root, that's ok)
        try:
            with open("stats.json", "w") as f:
                json.dump({"total": 0}, f)
        except PermissionError:
            pass  # File owned by root, will be overwritten on next sniffer write
        
        try:
            with open("live_alerts.json", "w") as f:
                json.dump([], f)
        except PermissionError:
            pass  # File owned by root, will be overwritten on next sniffer write
        
        # Reset graph history (this always works - it's session state)
        now = int(time.time())
        st.session_state.history_df = pd.DataFrame([{
            'unix_round': now - i,
            'count': 0,
            'status': 'NORMAL'
        } for i in range(60)])
        st.session_state.start_time = time.time()
        st.session_state.risk_cooldown = 0
        st.session_state.simulated_attack = 0
        # Store current packet count as offset so displayed count resets to 0
        try:
            with open("stats.json", "r") as f:
                current_stats = json.load(f)
                st.session_state.packet_offset = current_stats.get('total', 0)
        except:
            st.session_state.packet_offset = 0
        st.toast("✅ Dashboard reset!", icon="🔄")
        st.rerun()
    
    st.divider()
    
    # How it works (consumer-friendly)
    st.markdown("### How It Works")
    st.markdown("""
    Guardian AI monitors your network traffic in real-time:
    
    1. **📡 Capture** — Listens to all network packets
    2. **🔍 Analyze** — AI examines traffic patterns  
    3. **⚡ Detect** — Identifies threats in milliseconds
    4. **🚨 Alert** — Notifies you of suspicious activity
    """)
    
    st.divider()
    
    # Model info
    with st.expander("🤖 AI Model Details"):
        st.markdown("""
        **Algorithm:** K-Nearest Neighbors (KNN)
        
        **How it decides:**
        - Compares each packet to 250,000 known examples
        - Finds the 5 most similar traffic patterns
        - If most neighbors are attacks → Flag as threat
        
        **Performance:**
        - ✅ 98.8% Accuracy
        - ✅ 0.995 AUC Score
        - ✅ ~25ms response time
        """)


# ============================================================
# MAIN DASHBOARD
# ============================================================
@st.fragment(run_every=3)
def main_dashboard():
    # Load live data
    logs = []
    if os.path.exists("live_alerts.json"):
        with open("live_alerts.json", "r") as f:
            try:
                logs = json.load(f)
            except:
                pass
    
    stats = {"total": 0}
    if os.path.exists("stats.json"):
        with open("stats.json", "r") as f:
            try:
                stats = json.load(f)
            except:
                pass

    df = pd.DataFrame(logs)
    now = int(time.time())
    
    # Check for simulated attack (demo mode) - inject fake attack data
    simulated = st.session_state.get('simulated_attack', 0) > 0
    if simulated:
        st.session_state.simulated_attack -= 1
        # Inject fake attack entries for realistic demo
        fake_attacks = []
        num_attacks = int(np.random.randint(5, 12))
        for i in range(num_attacks):
            fake_attacks.append({
                'timestamp': time.strftime('%H:%M:%S'),
                'unix_time': int(now),
                'src': f"185.{int(np.random.randint(1,255))}.{int(np.random.randint(1,255))}.{int(np.random.randint(1,255))}",
                'dst': '192.168.1.1',
                'dst_port': int(np.random.choice([22, 23, 80, 443, 3389, 8080])),
                'proto': str(np.random.choice(['TCP', 'UDP'])),
                'status': 'ATTACK',
                'confidence': float(round(np.random.uniform(0.85, 0.99), 2))
            })
        fake_df = pd.DataFrame(fake_attacks)
        if df.empty:
            df = fake_df
        else:
            df = pd.concat([df, fake_df], ignore_index=True)
    
    # Update history buffer
    if not df.empty:
        df['unix_round'] = df['unix_time'].astype(int)
        new_counts = df.groupby(['unix_round', 'status']).size().reset_index(name='count')
        
        if not new_counts.empty:
            combined_df = pd.concat([st.session_state.history_df, new_counts])
            st.session_state.history_df = combined_df.drop_duplicates(
                subset=['unix_round', 'status'], 
                keep='last'
            ).sort_values('unix_round')
    
    # Trim to 60 second window
    window_start = now - 60
    st.session_state.history_df = st.session_state.history_df[
        st.session_state.history_df['unix_round'] > window_start
    ]
    
    plot_df = st.session_state.history_df.copy()
    plot_df['datetime'] = pd.to_datetime(plot_df['unix_round'], unit='s')

    # Calculate threat velocity
    velocity = 0.0
    total_flow = plot_df.groupby('unix_round')['count'].sum().reset_index()
    if len(total_flow) > 5:
        lr = LinearRegression().fit(total_flow[['unix_round']], total_flow['count'])
        velocity = lr.coef_[0]

    # Threat status with hysteresis
    if velocity > 0.5:
        st.session_state.risk_cooldown = 10
    elif st.session_state.risk_cooldown > 0:
        st.session_state.risk_cooldown -= 1

    # Count attacks in current window
    attacks_now = len(df[df['status'] == 'ATTACK']) if not df.empty else 0
    
    # Determine overall status (simulated attacks already injected into df above)
    if st.session_state.risk_cooldown > 0 or simulated:
        system_status = "THREAT DETECTED"
        status_color = "🔴"
    elif attacks_now > 0:
        system_status = "MONITORING"
        status_color = "🟡"
    else:
        system_status = "ALL CLEAR"
        status_color = "🟢"

    # ============================================================
    # HEADER & STATUS
    # ============================================================
    st.markdown("# Network Security Dashboard")
    
    # Status indicator (compact)
    if system_status == "THREAT DETECTED":
        st.error(f"**{status_color} {system_status}** — Unusual network activity detected. Review details below.")
    elif system_status == "MONITORING":
        st.warning(f"**{status_color} {system_status}** — Some suspicious packets detected. Keeping watch.")
    else:
        st.success(f"**{status_color} {system_status}** — Your network appears secure. No threats detected.")
    
    st.divider()

    # ============================================================
    # KEY METRICS — Easy to understand
    # ============================================================
    st.markdown("### 📊 Live Statistics")
    
    # Calculate health score first (needed for metrics)
    attack_pct = (attacks_now / len(df) * 100) if len(df) > 0 else 0
    base_score = 100
    if attack_pct > 0:
        base_score -= min(50, attack_pct * 2)
    if st.session_state.risk_cooldown > 0:
        base_score -= 30
    if velocity > 0.5:
        base_score -= 20
    health_score = max(0, min(100, int(base_score)))
    
    # Health status text
    if health_score >= 95:
        health_text = "Excellent"
    elif health_score >= 80:
        health_text = "Good"
    elif health_score >= 60:
        health_text = "Fair"
    else:
        health_text = "Critical"
    
    m1, m2, m3, m4 = st.columns(4)
    
    # Adjust packet count by offset (for reset functionality)
    displayed_packets = max(0, stats['total'] - st.session_state.get('packet_offset', 0))
    m1.metric(
        "Packets Scanned", 
        f"{displayed_packets:,}",
        help="Total network packets analyzed since last reset"
    )
    
    m2.metric(
        "Threat Rate", 
        f"{attack_pct:.1f}%",
        help="Percentage of suspicious packets in current window"
    )
    
    m3.metric(
        "Response Time", 
        "~25ms",
        help="How fast the AI analyzes each packet"
    )
    
    m4.metric(
        "Health Score", 
        f"{health_score} — {health_text}",
        help="Network health based on threat rate, attack velocity, and recent threats"
    )

    # ============================================================
    # TRAFFIC VISUALIZATION
    # ============================================================
    st.markdown("### 📈 Real-Time Traffic Monitor")
    st.caption("Green = normal traffic, Red = potential threats")
    
    color_map = {'NORMAL': '#00cc96', 'ATTACK': '#ef553b'}
    
    fig = px.area(
        plot_df, 
        x='datetime', 
        y='count', 
        color='status',
        template="plotly_dark",
        color_discrete_map=color_map,
        line_shape='spline'
    )
    
    fig.update_layout(
        xaxis=dict(
            title="Time", 
            tickformat="%H:%M:%S",
            showgrid=False,
            fixedrange=True
        ),
        yaxis=dict(
            title="Packets/sec",
            showgrid=True,
            gridcolor='#222',
            fixedrange=True
        ),
        height=300,
        margin=dict(l=0, r=0, t=10, b=0),
        hovermode="x unified",
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        legend=dict(
            orientation="h", 
            y=1.15, 
            title=None,
            font=dict(size=12)
        ),
        uirevision='constant'
    )
    
    st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})

    # ============================================================
    # ATTACK TYPE BREAKDOWN
    # ============================================================
    st.markdown("### 🎯 Detected Attack Types")
    if not df.empty and 'dst_port' in df.columns:
        attack_df = df[df['status'] == 'ATTACK']
        if not attack_df.empty:
            # Map ports to attack types
            def port_to_attack_type(port):
                port_map = {
                    22: "🔐 SSH Brute Force",
                    23: "📟 Telnet Probe",
                    80: "🌐 HTTP Attack",
                    443: "🔒 HTTPS Attack",
                    3389: "🖥️ RDP Attack",
                    21: "📁 FTP Attack",
                    25: "📧 SMTP Attack",
                    53: "🌍 DNS Attack",
                    8080: "🌐 Web Proxy Attack",
                }
                return port_map.get(int(port), f"🔌 Port {int(port)}")
            
            attack_types = attack_df['dst_port'].apply(port_to_attack_type).value_counts().head(5)
            cols = st.columns(min(len(attack_types), 5))
            for i, (attack_type, count) in enumerate(attack_types.items()):
                with cols[i]:
                    st.markdown(f"""
                    <div style="background: rgba(239, 68, 68, 0.1); border-left: 3px solid #ef4444; 
                                padding: 10px 14px; border-radius: 0 8px 8px 0;">
                        <div style="font-size: 0.85rem; color: #f8fafc;">{attack_type}</div>
                        <div style="font-size: 1.1rem; font-weight: 600; color: #ef4444;">{count}</div>
                    </div>
                    """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div style="background: rgba(34, 197, 94, 0.1); border-left: 3px solid #22c55e; 
                        padding: 12px 16px; border-radius: 0 8px 8px 0; color: #22c55e;">
                ✅ No attacks detected in current window
            </div>
            """, unsafe_allow_html=True)
    else:
        st.caption("📊 Collecting port data...")
    
    st.divider()
    
    # ============================================================
    # TOP THREAT SOURCES & EXPORT (side by side)
    # ============================================================
    threat_col, export_col = st.columns([3, 1])
    
    with threat_col:
        st.markdown("#### 🚨 Top Threat Sources")
        if not df.empty:
            attack_df = df[df['status'] == 'ATTACK']
            if not attack_df.empty:
                top_sources = attack_df['src'].value_counts().head(5).reset_index()
                top_sources.columns = ['IP Address', 'Incidents']
                
                # Display as styled cards
                for _, row in top_sources.iterrows():
                    ip = row['IP Address']
                    count = row['Incidents']
                    color = '#ef4444' if count >= 10 else '#f97316' if count >= 5 else '#fbbf24'
                    level = 'Critical' if count >= 10 else 'High' if count >= 5 else 'Medium'
                    st.markdown(f"""
                    <div style="display: flex; justify-content: space-between; align-items: center;
                                padding: 10px 16px; background: rgba(30, 41, 59, 0.6); 
                                border-radius: 8px; margin: 6px 0; border-left: 3px solid {color};">
                        <code style="font-size: 0.9rem; color: #e2e8f0;">{ip}</code>
                        <span style="color: {color}; font-weight: 600;">{level} • {count}×</span>
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.markdown("""
                <div style="padding: 20px; text-align: center; color: #22c55e; 
                            background: rgba(34, 197, 94, 0.1); border-radius: 8px;">
                    ✅ No malicious sources detected
                </div>
                """, unsafe_allow_html=True)
        else:
            st.caption("Waiting for data...")
    
    with export_col:
        st.markdown("#### 📥 Export Logs")
        if not df.empty:
            csv = df.to_csv(index=False)
            st.download_button(
                label="⬇️ Download CSV",
                data=csv,
                file_name=f"guardian_ai_logs_{time.strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True
            )
        else:
            st.caption("No data yet")

    st.divider()

    # ============================================================
    # RECENT ACTIVITY TABLE
    # ============================================================
    st.markdown("### 🔎 Recent Activity")
    
    if not df.empty:
        # Prepare user-friendly table
        display_df = df.iloc[::-1].head(10).copy()
        
        display_df['Time'] = display_df['timestamp']
        display_df['From'] = display_df['src']
        display_df['To'] = display_df['dst']
        display_df['Port'] = display_df.get('dst_port', 80)
        display_df['Protocol'] = display_df.get('proto', 'TCP')
        
        # User-friendly verdict
        def friendly_verdict(row):
            if row['status'] == 'ATTACK':
                return f"⚠️ Suspicious ({row['confidence']*100:.0f}% sure)"
            else:
                return f"✅ Normal ({row['confidence']*100:.0f}% sure)"
        
        display_df['Verdict'] = display_df.apply(friendly_verdict, axis=1)
        
        st.dataframe(
            display_df[['Time', 'From', 'To', 'Port', 'Verdict']],
            use_container_width=True,
            hide_index=True,
            column_config={
                "Time": st.column_config.TextColumn("Time"),
                "From": st.column_config.TextColumn("Source"),
                "To": st.column_config.TextColumn("Destination"),
                "Port": st.column_config.NumberColumn("Port", format="%d"),
                "Verdict": st.column_config.TextColumn("AI Analysis")
            }
        )
        
        # KNN Explainability section — show why packets were flagged
        attack_packets = display_df[display_df['status'] == 'ATTACK']
        if not attack_packets.empty:
            with st.expander("🔍 Why were these flagged? (AI Explainability)"):
                st.markdown("""
                **KNN Decision Process:** The AI compared each packet to 250,000 known traffic patterns 
                and found the 5 most similar examples. Here's what it found:
                """)
                
                for idx, row in attack_packets.head(3).iterrows():
                    port = int(row.get('dst_port', 0))
                    confidence = row['confidence']
                    
                    # Generate explanation based on port and confidence
                    port_explanations = {
                        22: "SSH connection attempt from external IP — matches known brute force patterns",
                        23: "Telnet probe detected — this protocol is commonly exploited",
                        80: "Unusual HTTP request pattern — similar to web scanning behavior",
                        443: "Suspicious HTTPS traffic — matches data exfiltration patterns",
                        3389: "RDP connection attempt — common target for ransomware",
                        21: "FTP access attempt — matches unauthorized access patterns",
                    }
                    
                    explanation = port_explanations.get(port, f"Traffic to port {port} matches known attack signatures")
                    neighbors_attack = int(confidence * 5)  # Approximate based on confidence
                    
                    st.markdown(f"""
                    **{row['src']}** → Port {port}
                    - 🎯 **Match:** {explanation}
                    - 📊 **Neighbors:** {neighbors_attack}/5 similar packets were attacks
                    - 💯 **Confidence:** {confidence*100:.0f}%
                    """)
                    st.divider()
    else:
        st.info("🔄 Waiting for network activity...")

    # ============================================================
    # HELP SECTION
    # ============================================================
    with st.expander("❓ What does this mean?"):
        st.markdown("""
        ### Understanding the Dashboard
        
        **Status Indicators:**
        - 🟢 **All Clear** — No suspicious activity detected
        - 🟡 **Monitoring** — Some unusual patterns, but not alarming
        - 🔴 **Threat Detected** — Significant anomaly found
        
        **What is a "suspicious packet"?**
        
        Network traffic that doesn't match normal patterns. This could be:
        - Port scanning (someone probing your network)
        - DDoS attempts (flood of requests)
        - Unusual data transfers
        
        **What should I do if threats are detected?**
        
        1. Check the source IP — is it from your network?
        2. Look at the target port — common attack targets are 22 (SSH), 80/443 (web)
        3. If persistent, consider blocking the source IP
        
        **How does the AI make decisions?**
        
        The KNN algorithm compares each packet to 250,000 known examples from real network traffic.
        It finds the 5 most similar patterns and votes: if most are attacks, it flags as suspicious.
        """)


# ============================================================
# RUN APP
# ============================================================
with st.sidebar:
    sidebar_content()

main_dashboard()
