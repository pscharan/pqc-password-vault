# Zero Trust Architecture (ZTA) Implementation
# Integrates with Open Policy Agent (OPA) for policy enforcement

import json
import time
import hashlib
import requests
import secrets
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import aiohttp
import asyncio
from functools import wraps
import logging
from ipaddress import ip_address, AddressValueError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RiskLevel(Enum):
    """Risk levels for ZTA decisions."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AccessDecision(Enum):
    """Access decision outcomes."""
    ALLOW = "allow"
    DENY = "deny"
    STEP_UP = "step_up"
    MONITOR = "monitor"

@dataclass
class DeviceContext:
    """Device context information for ZTA evaluation."""
    device_id: str
    ip_address: str
    user_agent: str
    geolocation: Optional[Dict[str, str]] = None
    device_fingerprint: Optional[str] = None
    last_seen: Optional[datetime] = None
    trusted_device: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for OPA evaluation."""
        result = asdict(self)
        if self.last_seen:
            result['last_seen'] = self.last_seen.isoformat()
        return result

@dataclass
class UserContext:
    """User context information for ZTA evaluation."""
    user_id: str
    vault_id: int
    session_id: str
    login_time: datetime
    previous_logins: List[Dict[str, Any]]
    failed_attempts: int = 0
    anomaly_score: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for OPA evaluation."""
        result = asdict(self)
        result['login_time'] = self.login_time.isoformat()
        return result

@dataclass
class RequestContext:
    """Request context for ZTA evaluation."""
    action: str
    resource: str
    timestamp: datetime
    request_id: str
    sensitivity_level: str = "standard"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for OPA evaluation."""
        result = asdict(self)
        result['timestamp'] = self.timestamp.isoformat()
        return result

class OPAClient:
    """Client for communicating with Open Policy Agent."""
    
    def __init__(self, opa_url: str = "http://localhost:8181"):
        self.opa_url = opa_url
        self.session = None
    
    async def evaluate_policy(self, policy_path: str, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate policy using OPA."""
        try:
            if not self.session:
                self.session = aiohttp.ClientSession()
            
            url = f"{self.opa_url}/v1/data/{policy_path}"
            
            async with self.session.post(
                url,
                json={"input": input_data},
                headers={"Content-Type": "application/json"}
            ) as response:
                
                if response.status == 200:
                    result = await response.json()
                    return result.get("result", {})
                else:
                    logger.error(f"OPA evaluation failed: {response.status}")
                    return {"allow": False, "reason": "OPA evaluation failed"}
        
        except Exception as e:
            logger.error(f"Error communicating with OPA: {e}")
            return {"allow": False, "reason": "Policy evaluation error"}
    
    async def close(self):
        """Close the HTTP session."""
        if self.session:
            await self.session.close()

class RiskScorer:
    """Calculates risk scores for ZTA decisions."""
    
    def __init__(self):
        self.risk_factors = {
            "new_device": 0.3,
            "unusual_location": 0.4,
            "unusual_time": 0.2,
            "multiple_failed_attempts": 0.5,
            "suspicious_user_agent": 0.3,
            "high_privilege_action": 0.4,
            "anomalous_behavior": 0.6
        }
    
    def calculate_device_risk(self, device_context: DeviceContext, 
                            user_context: UserContext) -> float:
        """Calculate risk score based on device context."""
        risk_score = 0.0
        
        # New device risk
        if not device_context.trusted_device:
            risk_score += self.risk_factors["new_device"]
        
        # Location-based risk
        if self._is_unusual_location(device_context, user_context):
            risk_score += self.risk_factors["unusual_location"]
        
        # Time-based risk
        if self._is_unusual_time(user_context):
            risk_score += self.risk_factors["unusual_time"]
        
        # Failed attempts risk
        if user_context.failed_attempts > 3:
            risk_score += self.risk_factors["multiple_failed_attempts"]
        
        # User agent risk
        if self._is_suspicious_user_agent(device_context.user_agent):
            risk_score += self.risk_factors["suspicious_user_agent"]
        
        return min(risk_score, 1.0)
    
    def calculate_action_risk(self, request_context: RequestContext) -> float:
        """Calculate risk score based on action being performed."""
        risk_score = 0.0
        
        # High-privilege actions
        high_privilege_actions = [
            "password_export",
            "vault_delete",
            "master_password_change",
            "share_password"
        ]
        
        if request_context.action in high_privilege_actions:
            risk_score += self.risk_factors["high_privilege_action"]
        
        # Sensitivity level
        if request_context.sensitivity_level == "high":
            risk_score += 0.3
        elif request_context.sensitivity_level == "critical":
            risk_score += 0.5
        
        return min(risk_score, 1.0)
    
    def _is_unusual_location(self, device_context: DeviceContext, 
                           user_context: UserContext) -> bool:
        """Check if location is unusual based on history."""
        if not device_context.geolocation or not user_context.previous_logins:
            return False
        
        # Simple geolocation check (in production, use more sophisticated methods)
        current_country = device_context.geolocation.get("country", "unknown")
        
        # Check if country appeared in last 10 logins
        recent_countries = set()
        for login in user_context.previous_logins[-10:]:
            if login.get("geolocation", {}).get("country"):
                recent_countries.add(login["geolocation"]["country"])
        
        return current_country not in recent_countries
    
    def _is_unusual_time(self, user_context: UserContext) -> bool:
        """Check if login time is unusual."""
        current_hour = user_context.login_time.hour
        
        # Check if current hour is outside normal hours (6 AM - 10 PM)
        if current_hour < 6 or current_hour > 22:
            return True
        
        # Check against historical patterns
        if user_context.previous_logins:
            historical_hours = [
                datetime.fromisoformat(login["timestamp"]).hour
                for login in user_context.previous_logins[-20:]
                if "timestamp" in login
            ]
            
            # If no historical data for this hour range, consider unusual
            hour_range = range(current_hour - 2, current_hour + 3)
            return not any(h in hour_range for h in historical_hours)
        
        return False
    
    def _is_suspicious_user_agent(self, user_agent: str) -> bool:
        """Check if user agent is suspicious."""
        suspicious_patterns = [
            "bot", "crawler", "spider", "scraper",
            "automated", "script", "curl", "wget"
        ]
        
        user_agent_lower = user_agent.lower()
        return any(pattern in user_agent_lower for pattern in suspicious_patterns)

class ZTAEngine:
    """Main Zero Trust Architecture engine."""
    
    def __init__(self, opa_client: OPAClient):
        self.opa_client = opa_client
        self.risk_scorer = RiskScorer()
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        self.policy_cache: Dict[str, Dict[str, Any]] = {}
        self.cache_ttl = 300  # 5 minutes
    
    async def evaluate_access(self, device_context: DeviceContext,
                            user_context: UserContext,
                            request_context: RequestContext) -> Tuple[AccessDecision, Dict[str, Any]]:
        """Evaluate access request using ZTA principles."""
        
        # Calculate risk scores
        device_risk = self.risk_scorer.calculate_device_risk(device_context, user_context)
        action_risk = self.risk_scorer.calculate_action_risk(request_context)
        total_risk = (device_risk + action_risk) / 2
        
        # Determine risk level
        if total_risk >= 0.8:
            risk_level = RiskLevel.CRITICAL
        elif total_risk >= 0.6:
            risk_level = RiskLevel.HIGH
        elif total_risk >= 0.4:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW
        
        # Prepare data for OPA evaluation
        opa_input = {
            "device": device_context.to_dict(),
            "user": user_context.to_dict(),
            "request": request_context.to_dict(),
            "risk_score": total_risk,
            "risk_level": risk_level.value
        }
        
        # Evaluate policy
        policy_result = await self.opa_client.evaluate_policy(
            "zta/access_control", opa_input
        )
        
        # Determine access decision
        decision = self._determine_decision(policy_result, risk_level)
        
        # Create response
        response = {
            "decision": decision.value,
            "risk_score": total_risk,
            "risk_level": risk_level.value,
            "device_risk": device_risk,
            "action_risk": action_risk,
            "policy_result": policy_result,
            "session_id": user_context.session_id,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        # Log decision
        logger.info(f"ZTA Decision: {decision.value} for user {user_context.user_id}, "
                   f"action {request_context.action}, risk {total_risk:.2f}")
        
        return decision, response
    
    def _determine_decision(self, policy_result: Dict[str, Any], 
                          risk_level: RiskLevel) -> AccessDecision:
        """Determine access decision based on policy result and risk level."""
        
        # Check explicit policy decision
        if "allow" in policy_result:
            if not policy_result["allow"]:
                return AccessDecision.DENY
        
        # Check for step-up authentication requirement
        if policy_result.get("step_up_required", False):
            return AccessDecision.STEP_UP
        
        # Risk-based decisions
        if risk_level == RiskLevel.CRITICAL:
            return AccessDecision.DENY
        elif risk_level == RiskLevel.HIGH:
            return AccessDecision.STEP_UP
        elif risk_level == RiskLevel.MEDIUM:
            return AccessDecision.MONITOR
        else:
            return AccessDecision.ALLOW
    
    async def continuous_verification(self, session_id: str) -> bool:
        """Perform continuous verification of active session."""
        if session_id not in self.active_sessions:
            return False
        
        session_data = self.active_sessions[session_id]
        
        # Check session expiry
        if datetime.fromisoformat(session_data["expires_at"]) < datetime.now(timezone.utc):
            del self.active_sessions[session_id]
            return False
        
        # Check for anomalous behavior
        if session_data.get("anomaly_score", 0) > 0.8:
            logger.warning(f"Session {session_id} flagged for anomalous behavior")
            return False
        
        # Update last verification time
        session_data["last_verified"] = datetime.now(timezone.utc).isoformat()
        
        return True
    
    def create_session(self, user_context: UserContext, 
                      device_context: DeviceContext) -> str:
        """Create a new ZTA session."""
        session_id = secrets.token_urlsafe(32)
        
        self.active_sessions[session_id] = {
            "user_id": user_context.user_id,
            "vault_id": user_context.vault_id,
            "device_id": device_context.device_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            "last_verified": datetime.now(timezone.utc).isoformat(),
            "anomaly_score": 0.0,
            "access_count": 0
        }
        
        return session_id
    
    def update_session_activity(self, session_id: str, activity: Dict[str, Any]):
        """Update session activity for continuous monitoring."""
        if session_id in self.active_sessions:
            session = self.active_sessions[session_id]
            session["access_count"] += 1
            session["last_activity"] = datetime.now(timezone.utc).isoformat()
            
            # Update anomaly score based on activity
            if activity.get("suspicious", False):
                session["anomaly_score"] += 0.1
            
            # Reset anomaly score over time
            if session["anomaly_score"] > 0:
                session["anomaly_score"] = max(0, session["anomaly_score"] - 0.01)
    
    def revoke_session(self, session_id: str):
        """Revoke a ZTA session."""
        if session_id in self.active_sessions:
            del self.active_sessions[session_id]
            logger.info(f"Session {session_id} revoked")

class ZTAMiddleware:
    """Middleware for ZTA enforcement in web applications."""
    
    def __init__(self, zta_engine: ZTAEngine):
        self.zta_engine = zta_engine
    
    def enforce_zta(self, required_actions: List[str] = None, 
                   sensitivity_level: str = "standard"):
        """Decorator for ZTA enforcement."""
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                # Extract context from request (implementation depends on framework)
                # This is a simplified example
                
                request = kwargs.get('request')
                if not request:
                    raise ValueError("Request object required for ZTA enforcement")
                
                # Create contexts
                device_context = DeviceContext(
                    device_id=request.headers.get("X-Device-ID", "unknown"),
                    ip_address=request.client.host,
                    user_agent=request.headers.get("User-Agent", "unknown")
                )
                
                user_context = UserContext(
                    user_id=request.state.user_id,
                    vault_id=request.state.vault_id,
                    session_id=request.state.session_id,
                    login_time=datetime.now(timezone.utc),
                    previous_logins=[]
                )
                
                request_context = RequestContext(
                    action=func.__name__,
                    resource=request.url.path,
                    timestamp=datetime.now(timezone.utc),
                    request_id=secrets.token_hex(8),
                    sensitivity_level=sensitivity_level
                )
                
                # Evaluate access
                decision, response = await self.zta_engine.evaluate_access(
                    device_context, user_context, request_context
                )
                
                # Handle decision
                if decision == AccessDecision.DENY:
                    raise HTTPException(status_code=403, detail="Access denied by ZTA policy")
                elif decision == AccessDecision.STEP_UP:
                    raise HTTPException(status_code=428, detail="Step-up authentication required")
                
                # Update session activity
                self.zta_engine.update_session_activity(
                    user_context.session_id,
                    {"action": func.__name__, "suspicious": False}
                )
                
                # Proceed with request
                return await func(*args, **kwargs)
            
            return wrapper
        return decorator

# Default OPA policies (in Rego format)
DEFAULT_OPA_POLICIES = {
    "zta/access_control": """
    package zta.access_control

    import rego.v1

    default allow := false
    default step_up_required := false

    # Allow low-risk requests
    allow if {
        input.risk_level == "low"
        input.device.trusted_device == true
    }

    # Require step-up for medium-risk requests
    step_up_required if {
        input.risk_level == "medium"
        input.request.sensitivity_level == "high"
    }

    # Require step-up for high-risk requests
    step_up_required if {
        input.risk_level == "high"
        input.device.trusted_device == true
    }

    # Deny critical risk requests
    allow if {
        input.risk_level == "critical"
        false
    }

    # Allow requests with explicit approval
    allow if {
        input.request.action == "password_retrieve"
        input.risk_level in ["low", "medium"]
        input.device.trusted_device == true
    }
    """
}

# Export main classes
__all__ = [
    "ZTAEngine",
    "OPAClient", 
    "RiskScorer",
    "ZTAMiddleware",
    "DeviceContext",
    "UserContext", 
    "RequestContext",
    "AccessDecision",
    "RiskLevel"
]
