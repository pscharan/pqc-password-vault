from fastapi import APIRouter, HTTPException, Depends, status, BackgroundTasks, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
import json
import logging
from .models import *
from .auth import get_current_session, create_access_token, revoke_session, cleanup_expired_sessions
from .utils import generate_password, validate_password_strength
from storage.vault import EnhancedVaultManager
from auth.zta import ZTAEngine, OPAClient, DeviceContext, UserContext, RequestContext, AccessDecision
from auth.webauthn import WebAuthnManager, WebAuthnConfig, StepUpAuthenticator
from crypto.pqc import PQCKeyManager, PQCEncryption, PQCSignature
import os
import secrets
import asyncio

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize router and managers
router = APIRouter()
security = HTTPBearer()

# Initialize enhanced vault manager with PostgreSQL
db_url = os.getenv("DATABASE_URL", "postgresql://vault_user:vault_password@localhost:5432/password_vault")
vault_manager = EnhancedVaultManager(db_url)

# Initialize ZTA components
opa_client = OPAClient(os.getenv("OPA_URL", "http://localhost:8181"))
zta_engine = ZTAEngine(opa_client)

# Initialize WebAuthn
webauthn_config = WebAuthnConfig(
    rp_id=os.getenv("WEBAUTHN_RP_ID", "localhost"),
    rp_name=os.getenv("WEBAUTHN_RP_NAME", "PQC Password Vault"),
    origin=os.getenv("WEBAUTHN_ORIGIN", "http://localhost:3000")
)
webauthn_manager = WebAuthnManager(webauthn_config)
step_up_authenticator = StepUpAuthenticator(webauthn_manager)

# Initialize PQC components
pqc_key_manager = PQCKeyManager()
pqc_encryption = PQCEncryption()
pqc_signature = PQCSignature()

# Background task to cleanup expired sessions
def cleanup_sessions_task():
    cleanup_expired_sessions()

async def get_device_context(request: Request) -> DeviceContext:
    """Extract device context from request."""
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "")
    device_id = request.headers.get("x-device-id", f"device_{secrets.token_hex(8)}")
    
    return DeviceContext(
        device_id=device_id,
        ip_address=client_ip,
        user_agent=user_agent,
        geolocation=None,  # Could be enhanced with IP geolocation
        device_fingerprint=None,
        trusted_device=False
    )

async def get_current_user_context(credentials: HTTPAuthorizationCredentials = Depends(security)) -> UserContext:
    """Get current user context from session."""
    try:
        session = await get_current_session(credentials)
        
        # Get user's previous login history (simplified)
        previous_logins = []  # Could be enhanced with actual history
        
        return UserContext(
            user_id=session.get("user_id", "unknown"),
            vault_id=session.get("vault_id", 0),
            session_id=session.get("session_id", ""),
            login_time=datetime.now(timezone.utc),
            previous_logins=previous_logins,
            failed_attempts=0,
            anomaly_score=0.0
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )

async def enforce_zta(action: str, resource: str, sensitivity_level: str = "standard"):
    """ZTA enforcement decorator."""
    def decorator(func):
        async def wrapper(request: Request, *args, **kwargs):
            try:
                # Get context
                device_context = await get_device_context(request)
                user_context = await get_current_user_context()
                
                request_context = RequestContext(
                    action=action,
                    resource=resource,
                    timestamp=datetime.now(timezone.utc),
                    request_id=f"req_{secrets.token_hex(8)}",
                    sensitivity_level=sensitivity_level
                )
                
                # Evaluate access with ZTA
                decision, evaluation_data = await zta_engine.evaluate_access(
                    device_context, user_context, request_context
                )
                
                # Handle decision
                if decision == AccessDecision.DENY:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Access denied by ZTA policy: {evaluation_data.get('reason', 'Unknown')}"
                    )
                elif decision == AccessDecision.STEP_UP:
                    # Return step-up challenge
                    step_up_challenge = step_up_authenticator.require_step_up(
                        user_context.user_id, action, user_context.session_id, sensitivity_level
                    )
                    raise HTTPException(
                        status_code=status.HTTP_428_PRECONDITION_REQUIRED,
                        detail={"step_up_required": True, "challenge": step_up_challenge}
                    )
                
                # Proceed with request
                return await func(request, *args, **kwargs)
                
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"ZTA enforcement error: {e}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Access evaluation failed"
                )
        return wrapper
    return decorator

# === VAULT MANAGEMENT ENDPOINTS ===

@router.post("/vault/create", response_model=VaultCreateResponse)
async def create_vault_endpoint(request: VaultCreateRequest, req: Request):
    """Creates a new PQC-enabled password vault."""
    try:
        device_context = await get_device_context(req)
        
        result = vault_manager.create_vault(
            vault_name=request.vault_name,
            master_password=request.master_password,
            user_id=request.user_id,
            device_context=device_context.to_dict()
        )
        
        if result["success"]:
            return VaultCreateResponse(
                success=True,
                vault_id=result["vault_id"],
                message=result["message"]
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result["error"]
            )
    except Exception as e:
        logger.error(f"Vault creation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.post("/vault/auth", response_model=VaultAuthResponse)
async def authenticate_vault_endpoint(request: VaultAuthRequest, req: Request, background_tasks: BackgroundTasks):
    """Authenticates access to a vault with ZTA evaluation."""
    try:
        device_context = await get_device_context(req)
        
        result = vault_manager.authenticate_vault(
            vault_name=request.vault_name,
            master_password=request.master_password,
            user_id=request.user_id,
            device_context=device_context.to_dict()
        )
        
        if result["success"]:
            # Create session token
            token = create_access_token(
                vault_id=result["vault_id"],
                vault_key=result["vault_key"],
                user_id=request.user_id,
                session_id=result["session_id"]
            )
            
            # Schedule session cleanup
            background_tasks.add_task(cleanup_sessions_task)
            
            return VaultAuthResponse(
                success=True,
                vault_id=result["vault_id"],
                session_token=token,
                session_id=result["session_id"],
                message=result["message"]
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=result["error"]
            )
    except Exception as e:
        logger.error(f"Vault authentication failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.post("/vault/logout")
async def logout_endpoint(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Logs out and revokes the current session."""
    try:
        session = await get_current_session(credentials)
        revoked = revoke_session(session["session_id"])
        return BaseResponse(
            success=True,
            message="Logged out successfully" if revoked else "Session already expired"
        )
    except Exception as e:
        logger.error(f"Logout failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

# === WEBAUTHN ENDPOINTS ===

@router.post("/webauthn/register/start")
async def start_webauthn_registration(request: Dict[str, Any], req: Request):
    """Start WebAuthn registration process."""
    try:
        result = webauthn_manager.start_registration(
            user_id=request["user_id"],
            username=request["username"],
            display_name=request.get("display_name", request["username"])
        )
        
        return result
    except Exception as e:
        logger.error(f"WebAuthn registration start failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.post("/webauthn/register/complete")
async def complete_webauthn_registration(request: Dict[str, Any], req: Request):
    """Complete WebAuthn registration process."""
    try:
        result = webauthn_manager.complete_registration(
            challenge_id=request["challenge_id"],
            credential_response=request["credential_response"]
        )
        
        return result
    except Exception as e:
        logger.error(f"WebAuthn registration completion failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.post("/webauthn/authenticate/start")
async def start_webauthn_authentication(request: Dict[str, Any], req: Request):
    """Start WebAuthn authentication process."""
    try:
        result = webauthn_manager.start_authentication(
            user_id=request["user_id"],
            allowed_credentials=request.get("allowed_credentials", [])
        )
        
        return result
    except Exception as e:
        logger.error(f"WebAuthn authentication start failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.post("/webauthn/authenticate/complete")
async def complete_webauthn_authentication(request: Dict[str, Any], req: Request):
    """Complete WebAuthn authentication process."""
    try:
        result = webauthn_manager.complete_authentication(
            challenge_id=request["challenge_id"],
            credential_response=request["credential_response"]
        )
        
        return result
    except Exception as e:
        logger.error(f"WebAuthn authentication completion failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.post("/webauthn/step-up/complete")
async def complete_step_up_authentication(request: Dict[str, Any], req: Request):
    """Complete step-up authentication process."""
    try:
        result = step_up_authenticator.complete_step_up(
            step_up_id=request["step_up_id"],
            credential_response=request["credential_response"]
        )
        
        return result
    except Exception as e:
        logger.error(f"Step-up authentication completion failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

# === PASSWORD MANAGEMENT ENDPOINTS ===

@router.post("/passwords", response_model=PasswordStoreResponse)
@enforce_zta("password_store", "vault_entry", "standard")
async def store_password_endpoint(
    request: PasswordStoreRequest,
    req: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Stores a new password entry using PQC encryption."""
    try:
        session = await get_current_session(credentials)
        device_context = await get_device_context(req)
        
        result = vault_manager.store_password_pqc(
            vault_id=session["vault_id"],
            vault_key=session["vault_key"],
            kyber_public_key=session["kyber_public_key"],
            sphincs_private_key=session["sphincs_private_key"],
            user_id=session["user_id"],
            service_name=request.service_name,
            username=request.username,
            password=request.password,
            notes=request.notes,
            website_url=request.website_url,
            tags=request.tags,
            device_context=device_context.to_dict()
        )
        
        if result["success"]:
            return PasswordStoreResponse(
                success=True,
                entry_id=result["entry_id"],
                message=result["message"]
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result["error"]
            )
    except Exception as e:
        logger.error(f"Password storage failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.get("/passwords/{service_name}", response_model=PasswordRetrieveResponse)
@enforce_zta("password_retrieve", "vault_entry", "high")
async def retrieve_password_endpoint(
    service_name: str,
    req: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Retrieves a password entry using PQC decryption."""
    try:
        session = await get_current_session(credentials)
        device_context = await get_device_context(req)
        
        result = vault_manager.retrieve_password_pqc(
            vault_id=session["vault_id"],
            vault_key=session["vault_key"],
            kyber_private_key=session["kyber_private_key"],
            service_name=service_name,
            user_id=session["user_id"],
            device_context=device_context.to_dict()
        )
        
        if result["success"]:
            return PasswordRetrieveResponse(
                success=True,
                entry=PasswordEntry(**result["entry"])
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=result["error"]
            )
    except Exception as e:
        logger.error(f"Password retrieval failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.get("/passwords", response_model=PasswordListResponse)
@enforce_zta("password_list", "vault", "standard")
async def list_passwords_endpoint(
    req: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Lists all password entries in the vault."""
    try:
        session = await get_current_session(credentials)
        
        result = vault_manager.list_services(session["vault_id"])
        
        if result["success"]:
            services = [PasswordEntryBasic(**service) for service in result["services"]]
            return PasswordListResponse(
                success=True,
                services=services,
                count=result["count"]
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result["error"]
            )
    except Exception as e:
        logger.error(f"Password listing failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.delete("/passwords/{entry_id}", response_model=BaseResponse)
@enforce_zta("password_delete", "vault_entry", "high")
async def delete_password_endpoint(
    entry_id: int,
    req: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Deletes a password entry (high sensitivity operation)."""
    try:
        session = await get_current_session(credentials)
        device_context = await get_device_context(req)
        
        result = vault_manager.delete_password(
            vault_id=session["vault_id"],
            entry_id=entry_id,
            user_id=session["user_id"],
            device_context=device_context.to_dict()
        )
        
        if result["success"]:
            return BaseResponse(
                success=True,
                message=result["message"]
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=result["error"]
            )
    except Exception as e:
        logger.error(f"Password deletion failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

# === UTILITY ENDPOINTS ===

@router.post("/passwords/generate", response_model=PasswordGenerateResponse)
async def generate_password_endpoint(request: PasswordGenerateRequest):
    """Generates a secure password."""
    try:
        password = generate_password(
            length=request.length,
            include_uppercase=request.include_uppercase,
            include_lowercase=request.include_lowercase,
            include_numbers=request.include_numbers,
            include_symbols=request.include_symbols
        )
        
        return PasswordGenerateResponse(
            success=True,
            password=password
        )
    except Exception as e:
        logger.error(f"Password generation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.post("/passwords/validate")
async def validate_password_endpoint(request: Dict[str, str]):
    """Validates password strength."""
    try:
        validation_result = validate_password_strength(request["password"])
        return {"success": True, "validation": validation_result}
    except Exception as e:
        logger.error(f"Password validation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.get("/health")
async def health_check():
    """Health check endpoint."""
    try:
        # Check database connectivity
        vault_manager.db.execute("SELECT 1")
        
        # Check OPA connectivity
        opa_status = await opa_client.evaluate_policy("health", {})
        
        return {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "services": {
                "database": "connected",
                "opa": "connected" if opa_status else "disconnected"
            }
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Service unhealthy: {str(e)}"
        )

# === ZTA MONITORING ENDPOINTS ===

@router.get("/zta/sessions")
async def get_active_sessions(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get active sessions for monitoring."""
    try:
        sessions = vault_manager.get_active_sessions()
        return {"success": True, "sessions": sessions}
    except Exception as e:
        logger.error(f"Session retrieval failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.get("/zta/audit")
async def get_audit_logs(
    hours: int = 24,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Get audit logs for monitoring."""
    try:
        logs = vault_manager.get_audit_logs(hours=hours)
        return {"success": True, "logs": logs}
    except Exception as e:
        logger.error(f"Audit log retrieval failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.get("/zta/policy-decisions")
async def get_policy_decisions(
    hours: int = 24,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Get policy decisions for monitoring."""
    try:
        decisions = vault_manager.get_policy_decisions(hours=hours)
        return {"success": True, "decisions": decisions}
    except Exception as e:
        logger.error(f"Policy decision retrieval failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        ) 