# Streamlit Dashboard for Real-time Credential Access Visualization
# PQC-ZTA Password Vault Monitoring Dashboard

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import psutil
import json
from datetime import datetime, timezone, timedelta
import time
import requests
from typing import Dict, List, Any
import os
import sys
import asyncio

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from storage.vault import EnhancedVaultManager, AuditEntry, UserSession, PolicyDecision
from auth.zta import ZTAEngine, RiskLevel, AccessDecision
from crypto.pqc import PQCKeyManager

# Configure Streamlit page
st.set_page_config(
    page_title="PQC-ZTA Password Vault Dashboard",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for dark theme
st.markdown("""
<style>
    .main {
        background-color: #0f1419;
        color: #ffffff;
    }
    .metric-card {
        background: linear-gradient(135deg, #1e3a8a 0%, #3730a3 100%);
        padding: 1rem;
        border-radius: 0.5rem;
        border: 1px solid #374151;
    }
    .risk-high {
        background-color: #dc2626;
        color: white;
        padding: 0.25rem 0.5rem;
        border-radius: 0.25rem;
    }
    .risk-medium {
        background-color: #f59e0b;
        color: white;
        padding: 0.25rem 0.5rem;
        border-radius: 0.25rem;
    }
    .risk-low {
        background-color: #059669;
        color: white;
        padding: 0.25rem 0.5rem;
        border-radius: 0.25rem;
    }
</style>
""", unsafe_allow_html=True)

class DashboardManager:
    """Manages dashboard data and real-time updates."""
    
    def __init__(self):
        """Initialize dashboard manager."""
        self.vault_manager = None
        self.api_base_url = "http://localhost:8000/api/v1"
        self._init_database()
    
    def _init_database(self):
        """Initialize database connection."""
        try:
            db_url = os.getenv(
                "DATABASE_URL", 
                "postgresql://vault_user:vault_password@localhost:5432/password_vault"
            )
            self.vault_manager = EnhancedVaultManager(db_url)
        except Exception as e:
            st.error(f"Failed to connect to database: {e}")
            self.vault_manager = None
    
    def get_system_metrics(self) -> Dict[str, Any]:
        """Get system performance metrics."""
        try:
            return {
                "cpu_percent": psutil.cpu_percent(interval=1),
                "memory_percent": psutil.virtual_memory().percent,
                "disk_percent": psutil.disk_usage('/').percent,
                "network_io": psutil.net_io_counters()._asdict(),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        except Exception as e:
            st.error(f"Failed to get system metrics: {e}")
            return {}
    
    def get_audit_data(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get audit log data for specified time period."""
        if not self.vault_manager:
            return []
        
        try:
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
            
            audit_entries = self.vault_manager.db.query(AuditEntry).filter(
                AuditEntry.timestamp >= cutoff_time
            ).order_by(AuditEntry.timestamp.desc()).limit(1000).all()
            
            return [
                {
                    "audit_id": entry.audit_id,
                    "action": entry.action,
                    "user_id": entry.user_id,
                    "vault_id": entry.vault_id,
                    "risk_score": entry.risk_score or 0.0,
                    "device_id": entry.device_id,
                    "ip_address": entry.ip_address,
                    "timestamp": entry.timestamp,
                    "has_signature": bool(entry.audit_signature)
                }
                for entry in audit_entries
            ]
        except Exception as e:
            st.error(f"Failed to get audit data: {e}")
            return []
    
    def get_session_data(self) -> List[Dict[str, Any]]:
        """Get active user sessions."""
        if not self.vault_manager:
            return []
        
        try:
            active_sessions = self.vault_manager.db.query(UserSession).filter(
                UserSession.is_active == True,
                UserSession.expires_at > datetime.now(timezone.utc)
            ).all()
            
            return [
                {
                    "session_id": session.session_id,
                    "user_id": session.user_id,
                    "vault_id": session.vault_id,
                    "device_id": session.device_id,
                    "ip_address": session.ip_address,
                    "risk_score": session.risk_score,
                    "anomaly_score": session.anomaly_score,
                    "created_at": session.created_at,
                    "last_activity": session.last_activity,
                    "expires_at": session.expires_at
                }
                for session in active_sessions
            ]
        except Exception as e:
            st.error(f"Failed to get session data: {e}")
            return []
    
    def get_policy_decisions(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get recent policy decisions."""
        if not self.vault_manager:
            return []
        
        try:
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
            
            decisions = self.vault_manager.db.query(PolicyDecision).filter(
                PolicyDecision.timestamp >= cutoff_time
            ).order_by(PolicyDecision.timestamp.desc()).limit(500).all()
            
            return [
                {
                    "decision_id": decision.decision_id,
                    "user_id": decision.user_id,
                    "action": decision.action,
                    "resource": decision.resource,
                    "decision": decision.decision,
                    "risk_score": decision.risk_score,
                    "risk_level": decision.risk_level,
                    "timestamp": decision.timestamp
                }
                for decision in decisions
            ]
        except Exception as e:
            st.error(f"Failed to get policy decisions: {e}")
            return []

def create_metrics_dashboard():
    """Create system metrics dashboard."""
    st.subheader("🖥️ System Performance")
    
    # Initialize dashboard manager
    if 'dashboard_manager' not in st.session_state:
        st.session_state.dashboard_manager = DashboardManager()
    
    dashboard_manager = st.session_state.dashboard_manager
    
    # Get system metrics
    metrics = dashboard_manager.get_system_metrics()
    
    if metrics:
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("CPU Usage", f"{metrics['cpu_percent']:.1f}%")
        
        with col2:
            st.metric("Memory Usage", f"{metrics['memory_percent']:.1f}%")
        
        with col3:
            st.metric("Disk Usage", f"{metrics['disk_percent']:.1f}%")

def create_audit_dashboard():
    """Create audit log visualization dashboard."""
    st.subheader("📊 Audit Log Analysis")
    
    dashboard_manager = st.session_state.dashboard_manager
    
    # Time period selector
    hours = st.selectbox("Time Period", [1, 6, 12, 24, 48, 168], index=3)
    
    # Get audit data
    audit_data = dashboard_manager.get_audit_data(hours)
    
    if audit_data:
        df = pd.DataFrame(audit_data)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Action frequency chart
        col1, col2 = st.columns(2)
        
        with col1:
            action_counts = df['action'].value_counts()
            fig_actions = px.bar(
                x=action_counts.values,
                y=action_counts.index,
                orientation='h',
                title="Most Frequent Actions",
                color=action_counts.values,
                color_continuous_scale="blues"
            )
            fig_actions.update_layout(
                template="plotly_dark",
                height=400
            )
            st.plotly_chart(fig_actions, use_container_width=True)
        
        with col2:
            # Risk score distribution
            fig_risk = px.histogram(
                df,
                x='risk_score',
                nbins=20,
                title="Risk Score Distribution",
                color_discrete_sequence=['#3b82f6']
            )
            fig_risk.update_layout(
                template="plotly_dark",
                height=400
            )
            st.plotly_chart(fig_risk, use_container_width=True)
        
        # Timeline of activities
        hourly_activity = df.set_index('timestamp').resample('H').size()
        fig_timeline = px.line(
            x=hourly_activity.index,
            y=hourly_activity.values,
            title="Activity Timeline (Hourly)",
            labels={'x': 'Time', 'y': 'Number of Actions'}
        )
        fig_timeline.update_layout(
            template="plotly_dark",
            height=300
        )
        st.plotly_chart(fig_timeline, use_container_width=True)
        
        # Recent audit entries table
        st.subheader("Recent Audit Entries")
        recent_audits = df.head(20)[['timestamp', 'action', 'user_id', 'risk_score', 'device_id', 'has_signature']]
        st.dataframe(recent_audits, use_container_width=True)
    
    else:
        st.info("No audit data available for the selected time period.")

def create_session_dashboard():
    """Create active sessions monitoring dashboard."""
    st.subheader("👥 Active Sessions")
    
    dashboard_manager = st.session_state.dashboard_manager
    
    # Get session data
    session_data = dashboard_manager.get_session_data()
    
    if session_data:
        df = pd.DataFrame(session_data)
        df['created_at'] = pd.to_datetime(df['created_at'])
        df['last_activity'] = pd.to_datetime(df['last_activity'])
        df['expires_at'] = pd.to_datetime(df['expires_at'])
        
        # Session metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Active Sessions", len(df))
        
        with col2:
            high_risk_sessions = len(df[df['risk_score'] > 0.7])
            st.metric("High Risk Sessions", high_risk_sessions)
        
        with col3:
            unique_users = df['user_id'].nunique()
            st.metric("Unique Users", unique_users)
        
        with col4:
            avg_risk = df['risk_score'].mean()
            st.metric("Average Risk Score", f"{avg_risk:.2f}")
        
        # Risk score vs anomaly score scatter plot
        fig_scatter = px.scatter(
            df,
            x='risk_score',
            y='anomaly_score',
            color='user_id',
            size='risk_score',
            hover_data=['device_id', 'ip_address'],
            title="Risk vs Anomaly Scores"
        )
        fig_scatter.update_layout(
            template="plotly_dark",
            height=400
        )
        st.plotly_chart(fig_scatter, use_container_width=True)
        
        # Sessions table
        st.subheader("Session Details")
        display_df = df[['user_id', 'device_id', 'ip_address', 'risk_score', 
                        'anomaly_score', 'last_activity', 'expires_at']]
        st.dataframe(display_df, use_container_width=True)
    
    else:
        st.info("No active sessions found.")

def create_zta_dashboard():
    """Create Zero Trust Architecture monitoring dashboard."""
    st.subheader("🛡️ Zero Trust Policy Decisions")
    
    dashboard_manager = st.session_state.dashboard_manager
    
    # Time period selector
    hours = st.selectbox("ZTA Time Period", [1, 6, 12, 24, 48], index=2, key="zta_hours")
    
    # Get policy decision data
    policy_data = dashboard_manager.get_policy_decisions(hours)
    
    if policy_data:
        df = pd.DataFrame(policy_data)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Decision summary
        col1, col2, col3, col4 = st.columns(4)
        
        decision_counts = df['decision'].value_counts()
        
        with col1:
            allow_count = decision_counts.get('allow', 0)
            st.metric("Allowed", allow_count, delta=None)
        
        with col2:
            deny_count = decision_counts.get('deny', 0)
            st.metric("Denied", deny_count, delta=None)
        
        with col3:
            step_up_count = decision_counts.get('step_up', 0)
            st.metric("Step-up Required", step_up_count, delta=None)
        
        with col4:
            monitor_count = decision_counts.get('monitor', 0)
            st.metric("Monitor", monitor_count, delta=None)
        
        # Policy decisions over time
        col1, col2 = st.columns(2)
        
        with col1:
            # Decision type distribution
            fig_pie = px.pie(
                values=decision_counts.values,
                names=decision_counts.index,
                title="Decision Distribution",
                color_discrete_sequence=['#10b981', '#ef4444', '#f59e0b', '#6366f1']
            )
            fig_pie.update_layout(
                template="plotly_dark",
                height=400
            )
            st.plotly_chart(fig_pie, use_container_width=True)
        
        with col2:
            # Risk level distribution
            risk_counts = df['risk_level'].value_counts()
            fig_risk_pie = px.pie(
                values=risk_counts.values,
                names=risk_counts.index,
                title="Risk Level Distribution",
                color_discrete_sequence=['#059669', '#f59e0b', '#dc2626', '#7c2d12']
            )
            fig_risk_pie.update_layout(
                template="plotly_dark",
                height=400
            )
            st.plotly_chart(fig_risk_pie, use_container_width=True)
        
        # Timeline of decisions
        decision_timeline = df.set_index('timestamp').resample('H')['decision'].count()
        fig_timeline = px.line(
            x=decision_timeline.index,
            y=decision_timeline.values,
            title="Policy Decisions Timeline (Hourly)"
        )
        fig_timeline.update_layout(
            template="plotly_dark",
            height=300
        )
        st.plotly_chart(fig_timeline, use_container_width=True)
        
        # Recent decisions table
        st.subheader("Recent Policy Decisions")
        recent_decisions = df.head(20)[['timestamp', 'user_id', 'action', 'decision', 'risk_level', 'risk_score']]
        st.dataframe(recent_decisions, use_container_width=True)
    
    else:
        st.info("No policy decision data available for the selected time period.")

def create_realtime_alerts():
    """Create real-time security alerts."""
    st.subheader("🚨 Real-time Security Alerts")
    
    dashboard_manager = st.session_state.dashboard_manager
    
    # Get recent high-risk activities
    audit_data = dashboard_manager.get_audit_data(1)  # Last hour
    session_data = dashboard_manager.get_session_data()
    
    alerts = []
    
    # Check for high-risk audit activities
    for audit in audit_data:
        if audit['risk_score'] and audit['risk_score'] > 0.8:
            alerts.append({
                "type": "High Risk Activity",
                "message": f"User {audit['user_id']} performed {audit['action']} with risk score {audit['risk_score']:.2f}",
                "timestamp": audit['timestamp'],
                "severity": "high"
            })
    
    # Check for high-risk sessions
    for session in session_data:
        if session['risk_score'] > 0.7:
            alerts.append({
                "type": "High Risk Session",
                "message": f"User {session['user_id']} has active session with risk score {session['risk_score']:.2f}",
                "timestamp": session['last_activity'],
                "severity": "medium"
            })
        
        if session['anomaly_score'] > 0.8:
            alerts.append({
                "type": "Anomalous Behavior",
                "message": f"User {session['user_id']} showing anomalous behavior (score: {session['anomaly_score']:.2f})",
                "timestamp": session['last_activity'],
                "severity": "high"
            })
    
    # Sort alerts by timestamp
    alerts.sort(key=lambda x: x['timestamp'], reverse=True)
    
    if alerts:
        for alert in alerts[:10]:  # Show latest 10 alerts
            severity_color = {
                "high": "🔴",
                "medium": "🟡",
                "low": "🟢"
            }
            
            st.markdown(f"""
            **{severity_color.get(alert['severity'], '🔵')} {alert['type']}**
            
            {alert['message']}
            
            *{alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S UTC')}*
            
            ---
            """)
    else:
        st.success("No security alerts at this time.")

def main():
    """Main dashboard application."""
    st.title("🔐 PQC-ZTA Password Vault Dashboard")
    st.markdown("**Real-time monitoring and visualization for Post-Quantum Cryptography Zero Trust Architecture Password Vault**")
    
    # Sidebar navigation
    st.sidebar.title("Navigation")
    page = st.sidebar.selectbox(
        "Choose a dashboard",
        ["Overview", "System Metrics", "Audit Logs", "Active Sessions", "ZTA Decisions", "Security Alerts"]
    )
    
    # Auto-refresh toggle
    auto_refresh = st.sidebar.checkbox("Auto-refresh (30s)", value=False)
    
    if auto_refresh:
        time.sleep(30)
        st.experimental_rerun()
    
    # Refresh button
    if st.sidebar.button("🔄 Refresh Data"):
        st.experimental_rerun()
    
    # Database connection status
    st.sidebar.markdown("---")
    st.sidebar.subheader("System Status")
    
    try:
        # Test database connection
        if 'dashboard_manager' in st.session_state:
            st.sidebar.success("✅ Database Connected")
        else:
            st.sidebar.error("❌ Database Disconnected")
    except:
        st.sidebar.error("❌ Database Error")
    
    # Route to appropriate dashboard
    if page == "Overview":
        create_metrics_dashboard()
        st.markdown("---")
        create_realtime_alerts()
    
    elif page == "System Metrics":
        create_metrics_dashboard()
    
    elif page == "Audit Logs":
        create_audit_dashboard()
    
    elif page == "Active Sessions":
        create_session_dashboard()
    
    elif page == "ZTA Decisions":
        create_zta_dashboard()
    
    elif page == "Security Alerts":
        create_realtime_alerts()
    
    # Footer
    st.markdown("---")
    st.markdown("*PQC-ZTA Password Vault Dashboard - Powered by Streamlit*")

if __name__ == "__main__":
    main() 