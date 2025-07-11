# WebAuthn Integration for Biometric Authentication
# Supports FIDO2 and step-up authentication as per project requirements

import json
import secrets
import base64
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timezone, timedelta
from webauthn import generate_registration_options, verify_registration_response
from webauthn import generate_authentication_options, verify_authentication_response
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    ResidentKeyRequirement,
    PublicKeyCredentialDescriptor,
    AuthenticatorTransport
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.exceptions import InvalidAuthenticationResponse, InvalidRegistrationResponse
import structlog
from dataclasses import dataclass
from enum import Enum

# Configure logging
logger = structlog.get_logger(__name__)

class AuthenticatorType(Enum):
    """Types of authenticators supported."""
    PLATFORM = "platform"  # Built-in biometric (Face ID, Touch ID, Windows Hello)
    CROSS_PLATFORM = "cross-platform"  # External security keys
    BOTH = "both"

class VerificationLevel(Enum):
    """User verification levels."""
    REQUIRED = "required"
    PREFERRED = "preferred"
    DISCOURAGED = "discouraged"

@dataclass
class WebAuthnConfig:
    """Configuration for WebAuthn operations."""
    rp_id: str
    rp_name: str
    origin: str
    timeout: int = 60000  # 60 seconds
    user_verification: VerificationLevel = VerificationLevel.PREFERRED
    authenticator_attachment: AuthenticatorType = AuthenticatorType.BOTH
    resident_key: bool = False
    
class WebAuthnCredential:
    """Represents a WebAuthn credential."""
    
    def __init__(self, credential_id: str, public_key: str, counter: int, 
                 user_id: str, authenticator_type: str, created_at: datetime):
        self.credential_id = credential_id
        self.public_key = public_key
        self.counter = counter
        self.user_id = user_id
        self.authenticator_type = authenticator_type
        self.created_at = created_at
        self.last_used = None
        self.usage_count = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "credential_id": self.credential_id,
            "public_key": self.public_key,
            "counter": self.counter,
            "user_id": self.user_id,
            "authenticator_type": self.authenticator_type,
            "created_at": self.created_at.isoformat(),
            "last_used": self.last_used.isoformat() if self.last_used else None,
            "usage_count": self.usage_count
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'WebAuthnCredential':
        """Create from dictionary."""
        credential = cls(
            credential_id=data["credential_id"],
            public_key=data["public_key"],
            counter=data["counter"],
            user_id=data["user_id"],
            authenticator_type=data["authenticator_type"],
            created_at=datetime.fromisoformat(data["created_at"])
        )
        
        if data.get("last_used"):
            credential.last_used = datetime.fromisoformat(data["last_used"])
        
        credential.usage_count = data.get("usage_count", 0)
        return credential

class WebAuthnManager:
    """Manages WebAuthn operations for biometric authentication."""
    
    def __init__(self, config: WebAuthnConfig):
        self.config = config
        self.credentials: Dict[str, WebAuthnCredential] = {}
        self.pending_registrations: Dict[str, Dict[str, Any]] = {}
        self.pending_authentications: Dict[str, Dict[str, Any]] = {}
    
    def start_registration(self, user_id: str, username: str, 
                         display_name: str, exclude_credentials: List[str] = None) -> Dict[str, Any]:
        """Start WebAuthn registration process."""
        try:
            # Generate user handle (should be unique and not personally identifiable)
            user_handle = base64.urlsafe_b64encode(
                f"user_{user_id}_{secrets.token_hex(8)}".encode()
            ).decode().rstrip('=')
            
            # Prepare excluded credentials
            excluded_credentials = []
            if exclude_credentials:
                for cred_id in exclude_credentials:
                    excluded_credentials.append(
                        PublicKeyCredentialDescriptor(
                            id=base64.urlsafe_b64decode(cred_id + '=='),
                            type="public-key"
                        )
                    )
            
            # Configure authenticator selection
            authenticator_selection = AuthenticatorSelectionCriteria(
                authenticator_attachment=self._get_authenticator_attachment(),
                resident_key=ResidentKeyRequirement.REQUIRED if self.config.resident_key else ResidentKeyRequirement.DISCOURAGED,
                user_verification=self._get_user_verification()
            )
            
            # Generate registration options
            registration_options = generate_registration_options(
                rp_id=self.config.rp_id,
                rp_name=self.config.rp_name,
                user_id=user_handle.encode(),
                user_name=username,
                user_display_name=display_name,
                exclude_credentials=excluded_credentials,
                authenticator_selection=authenticator_selection,
                attestation=AttestationConveyancePreference.DIRECT,
                supported_pub_key_algs=[
                    COSEAlgorithmIdentifier.ECDSA_SHA_256,
                    COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
                    COSEAlgorithmIdentifier.ECDSA_SHA_512,
                    COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_512,
                ],
                timeout=self.config.timeout
            )
            
            # Store challenge for verification
            challenge_id = secrets.token_urlsafe(32)
            self.pending_registrations[challenge_id] = {
                "challenge": base64.urlsafe_b64encode(registration_options.challenge).decode(),
                "user_id": user_id,
                "user_handle": user_handle,
                "username": username,
                "display_name": display_name,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
            }
            
            # Convert to JSON-serializable format
            options_json = {
                "challenge": base64.urlsafe_b64encode(registration_options.challenge).decode(),
                "rp": {
                    "name": registration_options.rp.name,
                    "id": registration_options.rp.id
                },
                "user": {
                    "id": base64.urlsafe_b64encode(registration_options.user.id).decode(),
                    "name": registration_options.user.name,
                    "displayName": registration_options.user.display_name
                },
                "pubKeyCredParams": [
                    {"alg": alg.alg, "type": "public-key"}
                    for alg in registration_options.pub_key_cred_params
                ],
                "timeout": registration_options.timeout,
                "excludeCredentials": [
                    {
                        "id": base64.urlsafe_b64encode(cred.id).decode(),
                        "type": cred.type,
                        "transports": cred.transports
                    }
                    for cred in registration_options.exclude_credentials
                ],
                "authenticatorSelection": {
                    "authenticatorAttachment": registration_options.authenticator_selection.authenticator_attachment,
                    "residentKey": registration_options.authenticator_selection.resident_key,
                    "userVerification": registration_options.authenticator_selection.user_verification
                },
                "attestation": registration_options.attestation
            }
            
            logger.info("WebAuthn registration started", user_id=user_id, challenge_id=challenge_id)
            
            return {
                "success": True,
                "challenge_id": challenge_id,
                "options": options_json
            }
            
        except Exception as e:
            logger.error("Failed to start WebAuthn registration", error=str(e))
            return {"success": False, "error": f"Registration failed: {e}"}
    
    def complete_registration(self, challenge_id: str, 
                            credential_response: Dict[str, Any]) -> Dict[str, Any]:
        """Complete WebAuthn registration process."""
        try:
            # Verify challenge exists and is valid
            if challenge_id not in self.pending_registrations:
                return {"success": False, "error": "Invalid or expired challenge"}
            
            registration_data = self.pending_registrations[challenge_id]
            
            # Check expiration
            if datetime.now(timezone.utc) > datetime.fromisoformat(registration_data["expires_at"]):
                del self.pending_registrations[challenge_id]
                return {"success": False, "error": "Registration challenge expired"}
            
            # Verify registration response
            verification = verify_registration_response(
                credential=credential_response,
                expected_challenge=base64.urlsafe_b64decode(registration_data["challenge"] + '=='),
                expected_origin=self.config.origin,
                expected_rp_id=self.config.rp_id
            )
            
            if not verification.verified:
                return {"success": False, "error": "Registration verification failed"}
            
            # Create credential record
            credential_id = base64.urlsafe_b64encode(verification.credential_id).decode()
            public_key = base64.urlsafe_b64encode(verification.credential_public_key).decode()
            
            credential = WebAuthnCredential(
                credential_id=credential_id,
                public_key=public_key,
                counter=verification.sign_count,
                user_id=registration_data["user_id"],
                authenticator_type=self._determine_authenticator_type(verification),
                created_at=datetime.now(timezone.utc)
            )
            
            # Store credential
            self.credentials[credential_id] = credential
            
            # Clean up pending registration
            del self.pending_registrations[challenge_id]
            
            logger.info("WebAuthn registration completed", 
                       user_id=registration_data["user_id"], 
                       credential_id=credential_id)
            
            return {
                "success": True,
                "credential_id": credential_id,
                "authenticator_type": credential.authenticator_type,
                "message": "Registration successful"
            }
            
        except InvalidRegistrationResponse as e:
            logger.error("Invalid WebAuthn registration response", error=str(e))
            return {"success": False, "error": f"Invalid registration response: {e}"}
        except Exception as e:
            logger.error("WebAuthn registration completion failed", error=str(e))
            return {"success": False, "error": f"Registration failed: {e}"}
    
    def start_authentication(self, user_id: str, 
                           allowed_credentials: List[str] = None) -> Dict[str, Any]:
        """Start WebAuthn authentication process."""
        try:
            # Prepare allowed credentials
            allow_credentials = []
            if allowed_credentials:
                for cred_id in allowed_credentials:
                    if cred_id in self.credentials:
                        allow_credentials.append(
                            PublicKeyCredentialDescriptor(
                                id=base64.urlsafe_b64decode(cred_id + '=='),
                                type="public-key",
                                transports=[AuthenticatorTransport.INTERNAL, AuthenticatorTransport.USB]
                            )
                        )
            
            # Generate authentication options
            authentication_options = generate_authentication_options(
                rp_id=self.config.rp_id,
                allow_credentials=allow_credentials,
                user_verification=self._get_user_verification(),
                timeout=self.config.timeout
            )
            
            # Store challenge for verification
            challenge_id = secrets.token_urlsafe(32)
            self.pending_authentications[challenge_id] = {
                "challenge": base64.urlsafe_b64encode(authentication_options.challenge).decode(),
                "user_id": user_id,
                "allowed_credentials": allowed_credentials or [],
                "created_at": datetime.now(timezone.utc).isoformat(),
                "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
            }
            
            # Convert to JSON-serializable format
            options_json = {
                "challenge": base64.urlsafe_b64encode(authentication_options.challenge).decode(),
                "timeout": authentication_options.timeout,
                "rpId": authentication_options.rp_id,
                "allowCredentials": [
                    {
                        "id": base64.urlsafe_b64encode(cred.id).decode(),
                        "type": cred.type,
                        "transports": cred.transports
                    }
                    for cred in authentication_options.allow_credentials
                ],
                "userVerification": authentication_options.user_verification
            }
            
            logger.info("WebAuthn authentication started", user_id=user_id, challenge_id=challenge_id)
            
            return {
                "success": True,
                "challenge_id": challenge_id,
                "options": options_json
            }
            
        except Exception as e:
            logger.error("Failed to start WebAuthn authentication", error=str(e))
            return {"success": False, "error": f"Authentication failed: {e}"}
    
    def complete_authentication(self, challenge_id: str, 
                              credential_response: Dict[str, Any]) -> Dict[str, Any]:
        """Complete WebAuthn authentication process."""
        try:
            # Verify challenge exists and is valid
            if challenge_id not in self.pending_authentications:
                return {"success": False, "error": "Invalid or expired challenge"}
            
            auth_data = self.pending_authentications[challenge_id]
            
            # Check expiration
            if datetime.now(timezone.utc) > datetime.fromisoformat(auth_data["expires_at"]):
                del self.pending_authentications[challenge_id]
                return {"success": False, "error": "Authentication challenge expired"}
            
            # Get credential ID from response
            credential_id = base64.urlsafe_b64encode(
                base64.urlsafe_b64decode(credential_response["id"] + '==')
            ).decode()
            
            # Find the credential
            if credential_id not in self.credentials:
                return {"success": False, "error": "Credential not found"}
            
            credential = self.credentials[credential_id]
            
            # Verify authentication response
            verification = verify_authentication_response(
                credential=credential_response,
                expected_challenge=base64.urlsafe_b64decode(auth_data["challenge"] + '=='),
                expected_origin=self.config.origin,
                expected_rp_id=self.config.rp_id,
                credential_public_key=base64.urlsafe_b64decode(credential.public_key + '=='),
                credential_current_sign_count=credential.counter
            )
            
            if not verification.verified:
                return {"success": False, "error": "Authentication verification failed"}
            
            # Update credential
            credential.counter = verification.new_sign_count
            credential.last_used = datetime.now(timezone.utc)
            credential.usage_count += 1
            
            # Clean up pending authentication
            del self.pending_authentications[challenge_id]
            
            logger.info("WebAuthn authentication completed", 
                       user_id=auth_data["user_id"], 
                       credential_id=credential_id)
            
            return {
                "success": True,
                "user_id": credential.user_id,
                "credential_id": credential_id,
                "authenticator_type": credential.authenticator_type,
                "message": "Authentication successful"
            }
            
        except InvalidAuthenticationResponse as e:
            logger.error("Invalid WebAuthn authentication response", error=str(e))
            return {"success": False, "error": f"Invalid authentication response: {e}"}
        except Exception as e:
            logger.error("WebAuthn authentication completion failed", error=str(e))
            return {"success": False, "error": f"Authentication failed: {e}"}
    
    def get_user_credentials(self, user_id: str) -> List[Dict[str, Any]]:
        """Get all credentials for a user."""
        user_credentials = []
        for credential in self.credentials.values():
            if credential.user_id == user_id:
                user_credentials.append({
                    "credential_id": credential.credential_id,
                    "authenticator_type": credential.authenticator_type,
                    "created_at": credential.created_at.isoformat(),
                    "last_used": credential.last_used.isoformat() if credential.last_used else None,
                    "usage_count": credential.usage_count
                })
        return user_credentials
    
    def delete_credential(self, credential_id: str, user_id: str) -> bool:
        """Delete a credential."""
        if credential_id in self.credentials:
            credential = self.credentials[credential_id]
            if credential.user_id == user_id:
                del self.credentials[credential_id]
                logger.info("WebAuthn credential deleted", 
                           user_id=user_id, credential_id=credential_id)
                return True
        return False
    
    def _get_authenticator_attachment(self) -> Optional[str]:
        """Get authenticator attachment preference."""
        if self.config.authenticator_attachment == AuthenticatorType.PLATFORM:
            return "platform"
        elif self.config.authenticator_attachment == AuthenticatorType.CROSS_PLATFORM:
            return "cross-platform"
        return None
    
    def _get_user_verification(self) -> str:
        """Get user verification requirement."""
        return self.config.user_verification.value
    
    def _determine_authenticator_type(self, verification) -> str:
        """Determine authenticator type from verification result."""
        # This is a simplified implementation
        # In practice, you'd inspect the attestation statement
        if hasattr(verification, 'attestation_object'):
            return "platform"  # Assume platform authenticator for now
        return "cross-platform"

class StepUpAuthenticator:
    """Handles step-up authentication for sensitive operations."""
    
    def __init__(self, webauthn_manager: WebAuthnManager):
        self.webauthn_manager = webauthn_manager
        self.step_up_sessions: Dict[str, Dict[str, Any]] = {}
    
    def require_step_up(self, user_id: str, action: str, 
                       session_id: str, sensitivity_level: str = "high") -> Dict[str, Any]:
        """Require step-up authentication for sensitive operation."""
        
        # Check if user has WebAuthn credentials
        user_credentials = self.webauthn_manager.get_user_credentials(user_id)
        if not user_credentials:
            return {
                "success": False,
                "error": "No biometric credentials registered",
                "requires_setup": True
            }
        
        # Start WebAuthn authentication
        allowed_credentials = [cred["credential_id"] for cred in user_credentials]
        auth_result = self.webauthn_manager.start_authentication(
            user_id=user_id,
            allowed_credentials=allowed_credentials
        )
        
        if not auth_result["success"]:
            return auth_result
        
        # Create step-up session
        step_up_id = secrets.token_urlsafe(32)
        self.step_up_sessions[step_up_id] = {
            "user_id": user_id,
            "action": action,
            "session_id": session_id,
            "sensitivity_level": sensitivity_level,
            "webauthn_challenge_id": auth_result["challenge_id"],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
        }
        
        return {
            "success": True,
            "step_up_id": step_up_id,
            "webauthn_options": auth_result["options"],
            "message": "Step-up authentication required"
        }
    
    def complete_step_up(self, step_up_id: str, 
                        credential_response: Dict[str, Any]) -> Dict[str, Any]:
        """Complete step-up authentication."""
        
        if step_up_id not in self.step_up_sessions:
            return {"success": False, "error": "Invalid step-up session"}
        
        step_up_data = self.step_up_sessions[step_up_id]
        
        # Check expiration
        if datetime.now(timezone.utc) > datetime.fromisoformat(step_up_data["expires_at"]):
            del self.step_up_sessions[step_up_id]
            return {"success": False, "error": "Step-up session expired"}
        
        # Complete WebAuthn authentication
        auth_result = self.webauthn_manager.complete_authentication(
            challenge_id=step_up_data["webauthn_challenge_id"],
            credential_response=credential_response
        )
        
        if not auth_result["success"]:
            return auth_result
        
        # Clean up step-up session
        del self.step_up_sessions[step_up_id]
        
        logger.info("Step-up authentication completed", 
                   user_id=step_up_data["user_id"], 
                   action=step_up_data["action"])
        
        return {
            "success": True,
            "user_id": step_up_data["user_id"],
            "action": step_up_data["action"],
            "session_id": step_up_data["session_id"],
            "message": "Step-up authentication successful"
        }

# Export main classes
__all__ = [
    "WebAuthnManager",
    "WebAuthnConfig",
    "WebAuthnCredential",
    "StepUpAuthenticator",
    "AuthenticatorType",
    "VerificationLevel"
] 