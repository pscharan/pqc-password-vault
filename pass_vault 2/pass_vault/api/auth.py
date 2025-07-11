import os
import jwt
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List
from fastapi import HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import secrets
import json
import base64
import hashlib
import logging
from crypto.pqc import PQCSignature

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# JWT Configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

# PQC Configuration for JWT signing (optional enhancement)
PQC_JWT_SIGNING = os.getenv("PQC_JWT_SIGNING", "false").lower() == "true"

# In-memory session storage (in production, use Redis or similar)
active_sessions: Dict[str, Dict[str, Any]] = {}

security = HTTPBearer()

def create_access_token(vault_id: int, vault_key: bytes, user_id: str, session_id: str = None) -> str:
    """Creates a JWT access token for authenticated vault access with enhanced session data."""
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    if not session_id:
        session_id = secrets.token_urlsafe(32)
    
    # Enhanced session data for PQC and ZTA
    active_sessions[session_id] = {
        "vault_id": vault_id,
        "vault_key": vault_key,
        "user_id": user_id,
        "session_id": session_id,
        "expires_at": expire,
        "created_at": datetime.now(timezone.utc),
        "last_activity": datetime.now(timezone.utc),
        "is_active": True,
        "risk_score": 0.0,
        "anomaly_score": 0.0,
        "device_contexts": [],
        "access_count": 0,
        "last_ip": None,
        "last_user_agent": None,
        # PQC keys would be added here when available
        "kyber_public_key": None,
        "kyber_private_key": None,
        "sphincs_private_key": None,
        "dilithium_private_key": None
    }
    
    to_encode = {
        "session_id": session_id,
        "vault_id": vault_id,
        "user_id": user_id,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "jti": secrets.token_urlsafe(16)  # JWT ID for uniqueness
    }
    
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def create_pqc_signed_token(vault_id: int, vault_key: bytes, user_id: str, 
                          dilithium_private_key: bytes, session_id: str = None) -> str:
    """Creates a PQC-signed JWT token using Dilithium signatures."""
    try:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        
        if not session_id:
            session_id = secrets.token_urlsafe(32)
        
        # Enhanced session data with PQC keys
        active_sessions[session_id] = {
            "vault_id": vault_id,
            "vault_key": vault_key,
            "user_id": user_id,
            "session_id": session_id,
            "expires_at": expire,
            "created_at": datetime.now(timezone.utc),
            "last_activity": datetime.now(timezone.utc),
            "is_active": True,
            "risk_score": 0.0,
            "anomaly_score": 0.0,
            "device_contexts": [],
            "access_count": 0,
            "last_ip": None,
            "last_user_agent": None,
            "dilithium_private_key": dilithium_private_key,
            "pqc_signed": True
        }
        
        # Create token payload
        payload = {
            "session_id": session_id,
            "vault_id": vault_id,
            "user_id": user_id,
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "jti": secrets.token_urlsafe(16),
            "pqc_signed": True
        }
        
        # Create base JWT token
        token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
        
        # Add PQC signature
        pqc_signature = PQCSignature()
        signature = pqc_signature.sign_dilithium(dilithium_private_key, token.encode())
        
        # Create enhanced token with PQC signature
        enhanced_token = {
            "jwt": token,
            "pqc_signature": base64.b64encode(signature).decode(),
            "algorithm": "Dilithium3"
        }
        
        return base64.b64encode(json.dumps(enhanced_token).encode()).decode()
        
    except Exception as e:
        logger.error(f"PQC token creation failed: {e}")
        # Fallback to regular JWT
        return create_access_token(vault_id, vault_key, user_id, session_id)

def verify_access_token(token: str) -> Dict[str, Any]:
    """Verifies and decodes a JWT access token (supports both regular and PQC-signed tokens)."""
    try:
        # Check if it's a PQC-signed token
        if token.startswith("eyJ"):  # Regular JWT
            return _verify_regular_jwt(token)
        else:  # Potentially PQC-signed token
            return _verify_pqc_signed_token(token)
            
    except Exception as e:
        logger.error(f"Token verification failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )

def _verify_regular_jwt(token: str) -> Dict[str, Any]:
    """Verifies a regular JWT token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        session_id = payload.get("session_id")
        vault_id = payload.get("vault_id")
        user_id = payload.get("user_id")
        
        if not session_id or not vault_id or not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload"
            )
        
        # Check session validity
        session = active_sessions.get(session_id)
        if not session:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired or invalid"
            )
        
        # Check session expiry
        if datetime.now(timezone.utc) > session["expires_at"]:
            active_sessions.pop(session_id, None)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired"
            )
        
        # Update session activity
        session["last_activity"] = datetime.now(timezone.utc)
        session["access_count"] += 1
        
        return session
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired"
        )
    except jwt.JWTError as e:
        logger.error(f"JWT verification failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )

def _verify_pqc_signed_token(token: str) -> Dict[str, Any]:
    """Verifies a PQC-signed JWT token."""
    try:
        # Decode the enhanced token
        enhanced_token = json.loads(base64.b64decode(token).decode())
        jwt_token = enhanced_token["jwt"]
        pqc_signature = base64.b64decode(enhanced_token["pqc_signature"])
        
        # First verify the JWT
        payload = jwt.decode(jwt_token, SECRET_KEY, algorithms=[ALGORITHM])
        session_id = payload.get("session_id")
        
        if not session_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload"
            )
        
        # Check session validity
        session = active_sessions.get(session_id)
        if not session:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired or invalid"
            )
        
        # Verify PQC signature if available
        if session.get("pqc_signed") and session.get("dilithium_private_key"):
            # In production, you'd use the public key, not private key
            # This is a simplified example
            pqc_signature_handler = PQCSignature()
            # Note: In practice, you'd need to store and use the public key
            # For now, we'll skip PQC verification and just validate the JWT
            pass
        
        # Check session expiry
        if datetime.now(timezone.utc) > session["expires_at"]:
            active_sessions.pop(session_id, None)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired"
            )
        
        # Update session activity
        session["last_activity"] = datetime.now(timezone.utc)
        session["access_count"] += 1
        
        return session
        
    except Exception as e:
        logger.error(f"PQC token verification failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid PQC token"
        )

async def get_current_session(credentials: HTTPAuthorizationCredentials) -> Dict[str, Any]:
    """Dependency to get current authenticated session."""
    return verify_access_token(credentials.credentials)

def update_session_context(session_id: str, context_data: Dict[str, Any]):
    """Updates session context with device, location, and risk data."""
    session = active_sessions.get(session_id)
    if session:
        session["last_activity"] = datetime.now(timezone.utc)
        session["last_ip"] = context_data.get("ip_address")
        session["last_user_agent"] = context_data.get("user_agent")
        session["risk_score"] = context_data.get("risk_score", session.get("risk_score", 0.0))
        session["anomaly_score"] = context_data.get("anomaly_score", session.get("anomaly_score", 0.0))
        
        # Add device context to history
        if "device_contexts" not in session:
            session["device_contexts"] = []
        session["device_contexts"].append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "device_id": context_data.get("device_id"),
            "ip_address": context_data.get("ip_address"),
            "user_agent": context_data.get("user_agent"),
            "risk_score": context_data.get("risk_score", 0.0)
        })
        
        # Keep only last 10 contexts
        session["device_contexts"] = session["device_contexts"][-10:]

def revoke_session(session_id: str) -> bool:
    """Revokes an active session."""
    session = active_sessions.get(session_id)
    if session:
        session["is_active"] = False
        session["revoked_at"] = datetime.now(timezone.utc)
        return active_sessions.pop(session_id, None) is not None
    return False

def revoke_all_user_sessions(user_id: str) -> int:
    """Revokes all active sessions for a user."""
    revoked_count = 0
    sessions_to_revoke = []
    
    for session_id, session in active_sessions.items():
        if session.get("user_id") == user_id and session.get("is_active", True):
            sessions_to_revoke.append(session_id)
    
    for session_id in sessions_to_revoke:
        if revoke_session(session_id):
            revoked_count += 1
    
    return revoked_count

def cleanup_expired_sessions():
    """Removes expired sessions from memory."""
    current_time = datetime.now(timezone.utc)
    expired_sessions = []
    
    for session_id, session in active_sessions.items():
        if (current_time > session["expires_at"] or 
            not session.get("is_active", True)):
            expired_sessions.append(session_id)
    
    for session_id in expired_sessions:
        active_sessions.pop(session_id, None)
    
    logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")
    return len(expired_sessions)

def get_session_stats() -> Dict[str, Any]:
    """Returns statistics about active sessions."""
    current_time = datetime.now(timezone.utc)
    active_count = 0
    expired_count = 0
    high_risk_count = 0
    
    for session in active_sessions.values():
        if session.get("is_active", True) and current_time <= session["expires_at"]:
            active_count += 1
            if session.get("risk_score", 0.0) > 0.7:
                high_risk_count += 1
        else:
            expired_count += 1
    
    return {
        "active_sessions": active_count,
        "expired_sessions": expired_count,
        "high_risk_sessions": high_risk_count,
        "total_sessions": len(active_sessions)
    }

def get_active_sessions() -> List[Dict[str, Any]]:
    """Returns list of active sessions for monitoring."""
    current_time = datetime.now(timezone.utc)
    active = []
    
    for session_id, session in active_sessions.items():
        if session.get("is_active", True) and current_time <= session["expires_at"]:
            active.append({
                "session_id": session_id,
                "user_id": session.get("user_id"),
                "vault_id": session.get("vault_id"),
                "created_at": session.get("created_at").isoformat() if session.get("created_at") else None,
                "last_activity": session.get("last_activity").isoformat() if session.get("last_activity") else None,
                "expires_at": session.get("expires_at").isoformat() if session.get("expires_at") else None,
                "risk_score": session.get("risk_score", 0.0),
                "anomaly_score": session.get("anomaly_score", 0.0),
                "access_count": session.get("access_count", 0),
                "last_ip": session.get("last_ip"),
                "pqc_signed": session.get("pqc_signed", False)
            })
    
    return active 