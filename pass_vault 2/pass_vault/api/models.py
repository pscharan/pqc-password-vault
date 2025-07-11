from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

# Request models
class VaultCreateRequest(BaseModel):
    vault_name: str = Field(..., min_length=1, max_length=100)
    master_password: str = Field(..., min_length=8)
    user_id: str = Field(..., min_length=1, max_length=100)

class VaultAuthRequest(BaseModel):
    vault_name: str = Field(..., min_length=1, max_length=100)
    master_password: str = Field(..., min_length=8)
    user_id: str = Field(..., min_length=1, max_length=100)

class PasswordStoreRequest(BaseModel):
    service_name: str = Field(..., min_length=1, max_length=100)
    username: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=1)
    notes: Optional[str] = None
    website_url: Optional[str] = None
    tags: Optional[List[str]] = []

class PasswordUpdateRequest(BaseModel):
    password: Optional[str] = None
    notes: Optional[str] = None
    website_url: Optional[str] = None
    tags: Optional[List[str]] = None

class PasswordSearchRequest(BaseModel):
    query: str = Field(..., min_length=1)

# WebAuthn models
class WebAuthnRegistrationStartRequest(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=100)
    username: str = Field(..., min_length=1, max_length=100)
    display_name: Optional[str] = None

class WebAuthnRegistrationCompleteRequest(BaseModel):
    challenge_id: str = Field(..., min_length=1)
    credential_response: Dict[str, Any]

class WebAuthnAuthenticationStartRequest(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=100)
    allowed_credentials: Optional[List[str]] = []

class WebAuthnAuthenticationCompleteRequest(BaseModel):
    challenge_id: str = Field(..., min_length=1)
    credential_response: Dict[str, Any]

class StepUpAuthenticationRequest(BaseModel):
    step_up_id: str = Field(..., min_length=1)
    credential_response: Dict[str, Any]

# PQC models
class PQCKeyGenerationRequest(BaseModel):
    key_type: str = Field(..., pattern="^(kyber|dilithium|sphincs)$")
    
class PQCEncryptionRequest(BaseModel):
    public_key: str = Field(..., min_length=1)
    plaintext: str = Field(..., min_length=1)
    
class PQCDecryptionRequest(BaseModel):
    private_key: str = Field(..., min_length=1)
    ciphertext: Dict[str, str]

class PQCSignatureRequest(BaseModel):
    private_key: str = Field(..., min_length=1)
    message: str = Field(..., min_length=1)
    algorithm: str = Field(..., pattern="^(dilithium|sphincs)$")

class PQCVerificationRequest(BaseModel):
    public_key: str = Field(..., min_length=1)
    message: str = Field(..., min_length=1)
    signature: str = Field(..., min_length=1)
    algorithm: str = Field(..., pattern="^(dilithium|sphincs)$")

# ZTA models
class ZTAEvaluationRequest(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=100)
    action: str = Field(..., min_length=1, max_length=100)
    resource: str = Field(..., min_length=1, max_length=100)
    device_context: Dict[str, Any]
    sensitivity_level: str = Field(default="standard", pattern="^(standard|high|critical)$")

class ZTAPolicyDecisionRequest(BaseModel):
    policy_name: str = Field(..., min_length=1, max_length=100)
    input_data: Dict[str, Any]

# Response models
class BaseResponse(BaseModel):
    success: bool
    message: Optional[str] = None
    error: Optional[str] = None

class VaultCreateResponse(BaseResponse):
    vault_id: Optional[int] = None

class VaultAuthResponse(BaseResponse):
    vault_id: Optional[int] = None
    session_token: Optional[str] = None
    session_id: Optional[str] = None

class PasswordEntry(BaseModel):
    id: int
    service_name: str
    username: str
    password: Optional[str] = None  # Only included in detail views
    notes: Optional[str] = None
    website_url: Optional[str] = None
    tags: List[str] = []
    created_at: str
    updated_at: str
    # PQC fields
    pqc_encrypted: Optional[bool] = False
    signature_verified: Optional[bool] = False

class PasswordEntryBasic(BaseModel):
    id: int
    service_name: str
    username: str
    website_url: Optional[str] = None
    tags: List[str] = []
    created_at: str
    updated_at: str
    pqc_encrypted: Optional[bool] = False

class PasswordStoreResponse(BaseResponse):
    entry_id: Optional[int] = None

class PasswordRetrieveResponse(BaseResponse):
    entry: Optional[PasswordEntry] = None

class PasswordListResponse(BaseResponse):
    services: List[PasswordEntryBasic] = []
    count: int = 0

class PasswordSearchResponse(BaseResponse):
    results: List[PasswordEntryBasic] = []
    count: int = 0

class PasswordGenerateRequest(BaseModel):
    length: int = Field(default=16, ge=8, le=128)
    include_uppercase: bool = True
    include_lowercase: bool = True
    include_numbers: bool = True
    include_symbols: bool = True

class PasswordGenerateResponse(BaseResponse):
    password: Optional[str] = None

# WebAuthn response models
class WebAuthnRegistrationStartResponse(BaseResponse):
    challenge_id: Optional[str] = None
    options: Optional[Dict[str, Any]] = None

class WebAuthnRegistrationCompleteResponse(BaseResponse):
    credential_id: Optional[str] = None
    verified: Optional[bool] = None

class WebAuthnAuthenticationStartResponse(BaseResponse):
    challenge_id: Optional[str] = None
    options: Optional[Dict[str, Any]] = None

class WebAuthnAuthenticationCompleteResponse(BaseResponse):
    verified: Optional[bool] = None
    user_id: Optional[str] = None

class StepUpAuthenticationResponse(BaseResponse):
    verified: Optional[bool] = None
    challenge_id: Optional[str] = None

# PQC response models
class PQCKeyGenerationResponse(BaseResponse):
    public_key: Optional[str] = None
    private_key: Optional[str] = None

class PQCEncryptionResponse(BaseResponse):
    ciphertext: Optional[Dict[str, str]] = None

class PQCDecryptionResponse(BaseResponse):
    plaintext: Optional[str] = None

class PQCSignatureResponse(BaseResponse):
    signature: Optional[str] = None

class PQCVerificationResponse(BaseResponse):
    verified: Optional[bool] = None

# ZTA response models
class ZTAEvaluationResponse(BaseResponse):
    decision: Optional[str] = None  # allow, deny, step_up, monitor
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    reason: Optional[str] = None
    step_up_required: Optional[bool] = None

class ZTAPolicyDecisionResponse(BaseResponse):
    decision: Optional[Dict[str, Any]] = None
    evaluation_time: Optional[float] = None

# Monitoring models
class SessionInfo(BaseModel):
    session_id: str
    user_id: str
    vault_id: int
    device_id: str
    ip_address: str
    risk_score: float
    created_at: str
    last_activity: str
    expires_at: str
    is_active: bool

class AuditLogEntry(BaseModel):
    audit_id: str
    action: str
    user_id: str
    vault_id: Optional[int] = None
    risk_score: Optional[float] = None
    device_id: Optional[str] = None
    ip_address: Optional[str] = None
    timestamp: str
    signature_verified: Optional[bool] = None

class PolicyDecisionEntry(BaseModel):
    decision_id: str
    user_id: str
    action: str
    resource: str
    decision: str
    risk_score: float
    risk_level: str
    timestamp: str

class SessionListResponse(BaseResponse):
    sessions: List[SessionInfo] = []
    count: int = 0

class AuditLogResponse(BaseResponse):
    logs: List[AuditLogEntry] = []
    count: int = 0

class PolicyDecisionResponse(BaseResponse):
    decisions: List[PolicyDecisionEntry] = []
    count: int = 0

# Health check models
class HealthCheckResponse(BaseResponse):
    status: str
    timestamp: str
    services: Dict[str, str] = {}
    uptime: Optional[float] = None 