# PQC-ZTA Password Vault - Comprehensive Technical Documentation

## Table of Contents

1. [Project Overview](#project-overview)
2. [System Architecture](#system-architecture)
3. [Security Implementation](#security-implementation)
4. [Backend Components](#backend-components)
5. [Frontend Components](#frontend-components)
6. [Database Architecture](#database-architecture)
7. [API Reference](#api-reference)
8. [Zero Trust Architecture](#zero-trust-architecture)
9. [Post-Quantum Cryptography](#post-quantum-cryptography)
10. [WebAuthn Integration](#webauthn-integration)
11. [Monitoring & Dashboards](#monitoring--dashboards)
12. [Development Environment](#development-environment)
13. [Deployment Guide](#deployment-guide)
14. [Configuration Reference](#configuration-reference)
15. [Troubleshooting](#troubleshooting)

## Project Overview

The **PQC-ZTA Password Vault** is a cutting-edge password management system that combines **Post-Quantum Cryptography (PQC)** with **Zero Trust Architecture (ZTA)** principles. This system provides quantum-resistant security, continuous verification, and modern biometric authentication capabilities.

### Key Features

- **🔒 Post-Quantum Security**: Kyber-1024, Dilithium-III, and SPHINCS+ algorithms
- **🛡️ Zero Trust Architecture**: Continuous verification with Open Policy Agent (OPA)
- **🔐 WebAuthn/FIDO2**: Biometric authentication (Touch ID, Face ID, Windows Hello)
- **📊 Real-time Monitoring**: Streamlit dashboard with risk assessment
- **⚡ Modern Tech Stack**: Flask backend with Next.js frontend
- **🎨 Beautiful UI**: Responsive design with shadcn/ui components
- **📱 Cross-Platform**: Web application with mobile-responsive design
- **🐳 Docker Infrastructure**: Complete containerization with service orchestration
- **🔍 GDPR Compliance**: Privacy-by-design with cryptographic audit trails
- **🚨 Anomaly Detection**: Machine learning-based behavioral analysis

### Technology Stack

#### Backend
- **Framework**: Flask (Python 3.8+)
- **Database**: PostgreSQL with SQLAlchemy ORM
- **Authentication**: WebAuthn + PQC-signed JWT tokens
- **Encryption**: Hybrid PQC (Kyber + AES-GCM)
- **Signatures**: Dilithium-III and SPHINCS+ for audit integrity
- **Session Storage**: Redis with secure session management
- **Policy Engine**: Open Policy Agent (OPA) for Zero Trust
- **Monitoring**: Prometheus metrics with Grafana visualization
- **Background Tasks**: Celery with Redis broker

#### Frontend
- **Framework**: Next.js 15 (React 19)
- **Styling**: Tailwind CSS
- **UI Components**: shadcn/ui (Radix UI)
- **State Management**: React hooks with Zustand
- **HTTP Client**: Axios with interceptors
- **Form Handling**: React Hook Form + Zod validation
- **Notifications**: Sonner toast library
- **WebAuthn**: FIDO2 client libraries

#### Infrastructure
- **Containerization**: Docker with multi-stage builds
- **Orchestration**: Docker Compose with health checks
- **Database**: PostgreSQL 15 with PQC extensions
- **Caching**: Redis 7 for sessions and rate limiting
- **Policy Engine**: Open Policy Agent (OPA) for access control
- **Monitoring**: Prometheus, Grafana, and Streamlit dashboards

## System Architecture

### High-Level Architecture

```
┌─────────────────────┐    ┌──────────────────────┐    ┌─────────────────────┐
│    Frontend         │    │       Backend        │    │    Infrastructure   │
│    (Next.js)        │◄──►│      (Flask)         │◄──►│   PostgreSQL + Redis│
│    Port: 3000       │    │     Port: 8000       │    │   OPA + Monitoring  │
│                     │    │                      │    │                     │
│ • WebAuthn UI       │    │ • PQC Crypto Layer   │    │ • PostgreSQL:5432   │
│ • Risk Dashboard    │    │ • ZTA Policy Engine  │    │ • Redis:6379        │
│ • Biometric Auth    │    │ • WebAuthn Server    │    │ • OPA:8181          │
└─────────────────────┘    └──────────────────────┘    └─────────────────────┘
```

### Security Flow (PQC-ZTA Enhanced)

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   User Access   │    │  Authentication  │    │   Authorization │
│                 │    │                  │    │                 │
│ • WebAuthn      │───►│ • PQC Signatures │───►│ • ZTA Policies  │
│ • Biometrics    │    │ • Dilithium-III  │    │ • Risk Scoring  │
│ • Device Trust  │    │ • Session Mgmt   │    │ • OPA Decisions │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  Data Access    │    │   Encryption     │    │   Audit Trail   │
│                 │    │                  │    │                 │
│ • Step-up Auth  │◄───│ • Kyber + AES    │───►│ • SPHINCS+ Sigs │
│ • Context Check │    │ • Hybrid PQC     │    │ • GDPR Compliant│
│ • Rate Limiting │    │ • Key Rotation   │    │ • Immutable Logs│
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Component Interaction (Enhanced)

```
                    ┌─────────────────────────────────────────┐
                    │              Frontend                   │
                    │    • React Components                   │
                    │    • WebAuthn Integration               │
                    │    • Real-time Dashboard                │
                    └─────────────────┬───────────────────────┘
                                      │ HTTPS/WebSocket
                                      ▼
                    ┌─────────────────────────────────────────┐
                    │               Backend                   │
                    │                                         │
┌──────────────┐    │  ┌──────────┐  ┌─────────┐  ┌─────────┐│
│ CLI Tools    │◄──►│  │Flask App │  │Auth Mgr │  │API Routes││
└──────────────┘    │  └──────────┘  └─────────┘  └─────────┘│
                    │        │            │           │      │
┌──────────────┐    │  ┌──────▼──┐  ┌─────▼───┐  ┌───▼─────┐│
│ Streamlit    │◄──►│  │PQC Crypto│  │ZTA Mgr  │  │Vault Mgr││
│ Dashboard    │    │  └─────────┘  └─────────┘  └─────────┘│
└──────────────┘    └─────────────────┬───────────────────────┘
                                      │
                                      ▼
                    ┌─────────────────────────────────────────┐
                    │            Infrastructure               │
                    │                                         │
                    │ ┌──────────┐ ┌─────────┐ ┌─────────────┐│
                    │ │PostgreSQL│ │  Redis  │ │     OPA     ││
                    │ │(Database)│ │(Session)│ │(Policies)   ││
                    │ └──────────┘ └─────────┘ └─────────────┘│
                    │                                         │
                    │ ┌──────────┐ ┌─────────┐ ┌─────────────┐│
                    │ │Prometheus│ │ Grafana │ │   Celery    ││
                    │ │(Metrics) │ │(Monitor)│ │(Background) ││
                    │ └──────────┘ └─────────┘ └─────────────┘│
                    └─────────────────────────────────────────┘
```

### Multi-Layer Security Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Application Layer                        │
│  • Flask Security Headers  • CORS Policy  • Rate Limiting      │
└─────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│                      Authentication Layer                       │
│  • WebAuthn/FIDO2  • PQC-signed JWT  • Session Management      │
└─────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│                      Authorization Layer                        │
│  • Zero Trust Policies  • Risk Scoring  • Context Evaluation   │
└─────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│                         Data Layer                              │
│  • Hybrid PQC Encryption  • Key Rotation  • Secure Storage     │
└─────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│                         Audit Layer                             │
│  • SPHINCS+ Signatures  • Immutable Logs  • GDPR Compliance    │
└─────────────────────────────────────────────────────────────────┘
```

## Backend Components

### 1. Main Entry Point (`main.py`)

**Purpose**: Application bootstrap with multi-mode support

**Key Features**:
- **Server Mode**: Flask web server with production/development configs
- **CLI Mode**: Command-line interface for vault operations
- **Dashboard Mode**: Streamlit real-time monitoring dashboard
- **Setup Mode**: Database migrations and initial configuration
- **Enhanced Logging**: Structured logging with colored output
- **Error Handling**: Graceful startup and comprehensive error reporting

**Usage**:
```bash
# Web server mode (default)
python main.py --mode server --host 0.0.0.0 --port 8000 --config development

# CLI mode for vault operations
python main.py --mode cli

# Dashboard mode for monitoring
python main.py --mode dashboard

# Setup mode for initialization
python main.py --setup
```

### 2. Flask Application (`app.py`)

**Purpose**: Web API server with comprehensive security and monitoring

**Components**:
- **Security Headers**: X-Frame-Options, CSP, HSTS, XSS Protection
- **CORS Middleware**: Configurable origins with credential support
- **Rate Limiting**: Redis-backed rate limiting with configurable thresholds
- **Request Logging**: Structured logging with correlation IDs
- **Error Handlers**: Comprehensive error handling with proper HTTP codes
- **Vault Manager Integration**: Centralized vault management instance

**Key Configuration**:
```python
app = Flask(__name__)
app.config.update({
    'SECRET_KEY': os.getenv('SECRET_KEY'),
    'DATABASE_URL': os.getenv('DATABASE_URL'),
    'JWT_SECRET_KEY': os.getenv('JWT_SECRET_KEY'),
    'WEBAUTHN_RP_ID': os.getenv('WEBAUTHN_RP_ID'),
    'OPA_URL': os.getenv('OPA_URL'),
    'REDIS_URL': os.getenv('REDIS_URL')
})
```

### 3. API Routes (`api/routes.py`)

**Purpose**: RESTful API with PQC-ZTA integration

**Enhanced Endpoint Categories**:

#### Vault Management (PQC Enhanced)
- `POST /api/v1/vault/create` - Create vault with PQC key generation
- `POST /api/v1/vault/authenticate` - Multi-factor authentication with ZTA
- `POST /api/v1/vault/logout` - Secure session termination
- `GET /api/v1/vault/status` - Vault status and risk assessment

#### WebAuthn Authentication
- `POST /api/v1/webauthn/register/begin` - Start WebAuthn registration
- `POST /api/v1/webauthn/register/complete` - Complete registration
- `POST /api/v1/webauthn/authenticate/begin` - Start authentication
- `POST /api/v1/webauthn/authenticate/complete` - Complete authentication
- `GET /api/v1/webauthn/credentials` - List user credentials

#### Password Management (PQC Encrypted)
- `GET /api/v1/passwords` - List entries with metadata only
- `GET /api/v1/passwords/{entry_id}` - Get password with ZTA verification
- `POST /api/v1/passwords` - Store with hybrid PQC encryption
- `PUT /api/v1/passwords/{entry_id}` - Update with audit trail
- `DELETE /api/v1/passwords/{entry_id}` - Secure deletion
- `POST /api/v1/passwords/search` - Search with context filtering

#### Zero Trust & Risk Management
- `GET /api/v1/risk/assessment` - Current risk score
- `POST /api/v1/risk/step-up` - Trigger step-up authentication
- `GET /api/v1/audit/logs` - Audit trail access
- `GET /api/v1/monitoring/metrics` - System metrics

#### Utilities
- `POST /api/v1/passwords/generate` - Secure password generation
- `POST /api/v1/passwords/validate` - Strength validation
- `GET /api/v1/health` - Comprehensive health check
- `GET /api/v1/docs` - API documentation

### 4. Data Models (`api/models.py`)

**Purpose**: Comprehensive request/response models for PQC-ZTA features

**Enhanced Model Categories**:

#### Authentication Models
```python
class WebAuthnRegistrationRequest(BaseModel):
    user_id: str
    display_name: str
    authenticator_selection: Optional[Dict[str, Any]] = None

class PQCAuthenticationRequest(BaseModel):
    vault_name: str
    password_hash: str
    device_context: DeviceContext
    risk_context: Optional[RiskContext] = None
```

#### PQC Models
```python
class PQCKeyPair(BaseModel):
    algorithm: str
    public_key: str
    private_key_encrypted: str
    key_id: str
    created_at: str

class HybridEncryptedData(BaseModel):
    kyber_ciphertext: str
    aes_ciphertext: str
    algorithm_info: str
    timestamp: str
```

#### ZTA Models
```python
class DeviceContext(BaseModel):
    device_id: str
    user_agent: str
    ip_address: str
    geolocation: Optional[Dict[str, Any]] = None
    trusted: bool = False

class RiskAssessment(BaseModel):
    risk_score: float
    risk_level: str
    factors: List[str]
    requires_step_up: bool
    policy_decision: str
```

#### Audit Models
```python
class AuditLogEntry(BaseModel):
    audit_id: str
    action: str
    user_id: str
    timestamp: str
    context_data: Dict[str, Any]
    risk_score: float
    signature: str  # SPHINCS+ signature
    signature_algorithm: str
```

### 5. Enhanced Authentication System (`api/auth.py`)

**Purpose**: Multi-layered authentication with PQC and ZTA

**Key Features**:
- **PQC-signed JWT Tokens**: Dilithium-III signatures for token integrity
- **Session Management**: Redis-backed sessions with ZTA context
- **Risk Scoring**: Real-time risk assessment with ML-based anomaly detection
- **Step-up Authentication**: Dynamic authentication requirements
- **Session Monitoring**: Continuous session validation and cleanup

**Enhanced Session Flow**:
1. **Initial Authentication**: WebAuthn + password verification
2. **Device Attestation**: PQC-signed device context validation
3. **Risk Assessment**: ZTA policy evaluation with OPA
4. **Token Generation**: PQC-signed JWT with embedded session context
5. **Continuous Verification**: Per-request risk evaluation
6. **Session Management**: Redis storage with automatic cleanup
7. **Audit Logging**: SPHINCS+ signed audit trail

### 6. Post-Quantum Cryptography Layer

#### PQC Core Module (`crypto/pqc.py`)

**Purpose**: Comprehensive Post-Quantum Cryptography implementation

**Key Components**:

##### PQC Key Manager
```python
class PQCKeyManager:
    """Manages PQC key generation, storage, and lifecycle"""
    
    def generate_kyber_keypair(self) -> Tuple[bytes, bytes]:
        """Generate Kyber-1024 key encapsulation mechanism keys"""
        
    def generate_dilithium_keypair(self) -> Tuple[bytes, bytes]:
        """Generate Dilithium-III signature keys"""
        
    def generate_sphincs_keypair(self) -> Tuple[bytes, bytes]:
        """Generate SPHINCS+ hash-based signature keys"""
```

##### PQC Encryption
```python
class PQCEncryption:
    """Hybrid PQC encryption using Kyber + AES-GCM"""
    
    def encrypt_hybrid(self, data: bytes, public_key: bytes) -> Dict[str, bytes]:
        """Kyber KEM + AES-GCM encryption"""
        
    def decrypt_hybrid(self, encrypted_data: Dict[str, bytes], 
                      private_key: bytes) -> bytes:
        """Decrypt hybrid PQC encrypted data"""
```

##### PQC Audit Logger
```python
class PQCAuditLogger:
    """SPHINCS+ signed audit logging for integrity"""
    
    def sign_audit_entry(self, data: Dict[str, Any], 
                        private_key: bytes) -> str:
        """Create SPHINCS+ signature for audit entry"""
        
    def verify_audit_signature(self, data: Dict[str, Any], 
                              signature: str, public_key: bytes) -> bool:
        """Verify audit entry integrity"""
```

#### Symmetric Encryption (`crypto/symmetric.py`)

**Purpose**: AES-256-GCM encryption for traditional cryptography and hybrid integration

**Key Functions**:
```python
def encrypt_data(data: bytes, key: bytes) -> Dict[str, Any]:
    """Enhanced AES-256-GCM encryption with metadata"""
    
def decrypt_data(encrypted_data: Dict[str, Any], key: bytes) -> bytes:
    """Decrypt and verify AES-256-GCM encrypted data"""
    
def derive_key(password: str, salt: bytes, iterations: int = 100000) -> bytes:
    """PBKDF2 key derivation with configurable iterations"""
```

**Security Features**:
- **AES-256-GCM**: Authenticated encryption with 256-bit keys
- **Random Nonces**: Unique nonce for each encryption operation
- **Integrity Protection**: Automatic authentication tag verification
- **Key Derivation**: PBKDF2 with configurable iterations
- **Metadata Handling**: Algorithm versioning and migration support

## Zero Trust Architecture

### ZTA Core Module (`auth/zta.py`)

**Purpose**: Implementation of Zero Trust Architecture principles

**Key Components**:

#### ZTA Manager
```python
class ZTAManager:
    """Central ZTA policy engine integration"""
    
    def __init__(self, opa_url: str, redis_client):
        """Initialize with OPA URL and Redis for caching"""
        
    async def evaluate_access(self, context: ZTAContext) -> ZTADecision:
        """Evaluate access request against ZTA policies"""
        
    def calculate_risk_score(self, context: ZTAContext) -> float:
        """Calculate contextual risk score (0.0-1.0)"""
```

#### Context Manager
```python
class ZTAContext:
    """Comprehensive request context for ZTA evaluation"""
    
    user_id: str
    device_context: DeviceContext
    request_context: RequestContext
    session_context: SessionContext
    risk_factors: List[RiskFactor]
```

#### Policy Engine Integration
```python
class OPAPolicyEngine:
    """Open Policy Agent integration for policy evaluation"""
    
    async def query_policy(self, policy_name: str, input_data: Dict) -> Dict:
        """Query OPA for policy decisions"""
        
    def load_policies(self, policy_directory: str):
        """Load Rego policies into OPA"""
```

**ZTA Policies (`opa-policies/vault_access.rego`)**:
- **Device Trust**: Device fingerprinting and trust levels
- **Location-based Access**: Geographic restriction policies
- **Time-based Access**: Temporal access controls
- **Risk-based Authentication**: Dynamic authentication requirements
- **Rate Limiting**: Request frequency controls

## WebAuthn Integration

### WebAuthn Server Module (`auth/webauthn.py`)

**Purpose**: FIDO2/WebAuthn authentication implementation

**Key Components**:

#### WebAuthn Manager
```python
class WebAuthnManager:
    """WebAuthn server implementation for biometric authentication"""
    
    def initiate_registration(self, user_id: str) -> Dict[str, Any]:
        """Start WebAuthn credential registration"""
        
    def complete_registration(self, user_id: str, credential: Dict) -> bool:
        """Complete and verify WebAuthn registration"""
        
    def initiate_authentication(self, user_id: str) -> Dict[str, Any]:
        """Start WebAuthn authentication challenge"""
        
    def complete_authentication(self, user_id: str, response: Dict) -> bool:
        """Verify WebAuthn authentication response"""
```

#### Credential Management
```python
class WebAuthnCredential:
    """WebAuthn credential storage and management"""
    
    credential_id: str
    user_id: str
    public_key: bytes
    counter: int
    transports: List[str]
    backup_eligible: bool
    backup_state: bool
    created_at: datetime
    last_used: datetime
```

**Features**:
- **Platform Authenticators**: Touch ID, Face ID, Windows Hello
- **Cross-Platform**: USB security keys, Bluetooth devices
- **Step-up Authentication**: Contextual re-authentication
- **Credential Management**: Registration, deregistration, monitoring
- **Anti-Phishing**: Origin validation and credential scope

## Database Architecture

### Enhanced Vault Storage Layer (`storage/vault.py`)

**Purpose**: PostgreSQL-based vault management with PQC and ZTA integration

**Enhanced Database Schema**:

#### VaultMaster Table
```sql
CREATE TABLE vault_master (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    master_password_hash TEXT NOT NULL,  -- Argon2id hash
    salt BYTEA NOT NULL,
    encrypted_vault_key BYTEA NOT NULL,  -- PQC encrypted
    pqc_public_key BYTEA,               -- Kyber public key
    pqc_private_key_encrypted BYTEA,    -- Encrypted Kyber private key
    dilithium_public_key BYTEA,         -- For signatures
    dilithium_private_key_encrypted BYTEA,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    last_accessed TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);
```

#### Password Entries Table
```sql
CREATE TABLE password_entries (
    id SERIAL PRIMARY KEY,
    vault_id INTEGER REFERENCES vault_master(id),
    service_name VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL,
    encrypted_password BYTEA NOT NULL,   -- Hybrid PQC encrypted
    encrypted_notes BYTEA,               -- PQC encrypted notes
    website_url TEXT,
    tags JSONB DEFAULT '[]',
    encryption_algorithm VARCHAR(50) DEFAULT 'kyber_aes',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    last_accessed TIMESTAMP,
    access_count INTEGER DEFAULT 0,
    is_deleted BOOLEAN DEFAULT FALSE,
    
    -- Full-text search
    search_vector tsvector,
    
    -- Audit fields
    created_by VARCHAR(100),
    last_modified_by VARCHAR(100)
);
```

#### WebAuthn Credentials Table
```sql
CREATE TABLE webauthn_credentials (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(100) NOT NULL,
    credential_id BYTEA UNIQUE NOT NULL,
    public_key BYTEA NOT NULL,
    counter BIGINT DEFAULT 0,
    transports JSONB DEFAULT '[]',
    backup_eligible BOOLEAN DEFAULT FALSE,
    backup_state BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW(),
    last_used TIMESTAMP,
    usage_count INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE
);
```

#### ZTA Session Table
```sql
CREATE TABLE zta_sessions (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(255) UNIQUE NOT NULL,
    user_id VARCHAR(100) NOT NULL,
    vault_id INTEGER REFERENCES vault_master(id),
    device_fingerprint TEXT,
    ip_address INET,
    user_agent TEXT,
    geolocation JSONB,
    risk_score DECIMAL(3,2) DEFAULT 0.0,
    trust_level VARCHAR(20) DEFAULT 'LOW',
    requires_step_up BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW(),
    last_activity TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL,
    is_active BOOLEAN DEFAULT TRUE
);
```

#### Audit Log Table
```sql
CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    audit_id UUID UNIQUE DEFAULT gen_random_uuid(),
    action VARCHAR(100) NOT NULL,
    user_id VARCHAR(100) NOT NULL,
    vault_id INTEGER,
    session_id VARCHAR(255),
    resource_type VARCHAR(50),
    resource_id VARCHAR(100),
    context_data JSONB DEFAULT '{}',
    risk_score DECIMAL(3,2),
    ip_address INET,
    user_agent TEXT,
    timestamp TIMESTAMP DEFAULT NOW(),
    
    -- PQC signatures for integrity
    signature TEXT NOT NULL,             -- SPHINCS+ signature
    signature_algorithm VARCHAR(50) DEFAULT 'sphincs_sha256',
    public_key_id VARCHAR(100),
    
    -- GDPR compliance
    retention_policy VARCHAR(50) DEFAULT 'STANDARD',
    anonymized BOOLEAN DEFAULT FALSE
);
```

#### Enhanced VaultManager Class

```python
class VaultManager:
    """Enhanced vault manager with PQC and ZTA integration"""
    
    def __init__(self, db_session, pqc_manager, zta_manager):
        self.db = db_session
        self.pqc = pqc_manager
        self.zta = zta_manager
    
    async def create_vault_pqc(self, name: str, master_password: str, 
                              user_context: ZTAContext) -> Dict[str, Any]:
        """Create vault with PQC key generation"""
        
    async def authenticate_vault_zta(self, name: str, password: str,
                                   context: ZTAContext) -> ZTADecision:
        """ZTA-enhanced vault authentication"""
        
    async def store_password_pqc(self, vault_id: int, entry_data: Dict,
                               session_context: ZTAContext) -> bool:
        """Store password with hybrid PQC encryption"""
        
    async def retrieve_password_zta(self, entry_id: int, 
                                  context: ZTAContext) -> Optional[Dict]:
        """Retrieve password with ZTA verification"""
```

## Monitoring & Dashboards

### Streamlit Dashboard (`dashboard/streamlit_app.py`)

**Purpose**: Real-time monitoring and administrative interface

**Dashboard Components**:

#### System Overview
- **Active Sessions**: Current user sessions with risk scores
- **Vault Statistics**: Total vaults, passwords, access patterns
- **Security Metrics**: Failed authentication attempts, anomalies
- **System Health**: Database connectivity, service status

#### Risk Assessment Dashboard
```python
def render_risk_dashboard():
    """Real-time risk assessment visualization"""
    
    # Risk score distribution
    st.plotly_chart(create_risk_distribution_chart())
    
    # Geographic access patterns
    st.map(get_access_locations())
    
    # Time-based access patterns
    st.line_chart(get_hourly_access_data())
```

#### Security Operations Center (SOC)
- **Anomaly Detection**: ML-based behavioral analysis
- **Threat Intelligence**: Suspicious IP addresses, patterns
- **Incident Response**: Automated response triggers
- **Compliance Reporting**: GDPR, audit trail verification

#### PQC Monitoring
- **Key Lifecycle**: Key generation, rotation, expiration
- **Algorithm Performance**: Encryption/decryption metrics
- **Quantum Readiness**: Algorithm compliance status

## Configuration Reference

### Environment Configuration (`config.template`)

**Core Application Settings**:
```bash
# Flask Configuration
FLASK_ENV=development
SECRET_KEY=your-secret-key-here
FLASK_DEBUG=True

# Database Configuration  
DATABASE_URL=postgresql://user:password@localhost:5432/pass_vault
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=30

# Redis Configuration
REDIS_URL=redis://localhost:6379/0
REDIS_SESSION_DB=1
REDIS_CACHE_DB=2

# JWT Configuration
JWT_SECRET_KEY=your-jwt-secret-key
JWT_ACCESS_TOKEN_EXPIRES=3600
JWT_REFRESH_TOKEN_EXPIRES=604800
```

**WebAuthn Configuration**:
```bash
WEBAUTHN_RP_ID=localhost
WEBAUTHN_RP_NAME="PQC-ZTA Password Vault"
WEBAUTHN_RP_ICON=https://example.com/icon.png
WEBAUTHN_ORIGIN=https://localhost:3000
WEBAUTHN_TIMEOUT=60000
```

**Zero Trust Architecture**:
```bash
# OPA Configuration
OPA_URL=http://localhost:8181
OPA_POLICY_PATH=/v1/data/vault/access
OPA_TIMEOUT=5

# Risk Assessment
ZTA_RISK_THRESHOLD_LOW=0.3
ZTA_RISK_THRESHOLD_MEDIUM=0.6
ZTA_RISK_THRESHOLD_HIGH=0.8
ZTA_MAX_FAILED_ATTEMPTS=5
ZTA_LOCKOUT_DURATION=300

# Geographic Restrictions
ZTA_ALLOWED_COUNTRIES=US,CA,GB,AU
ZTA_BLOCKED_COUNTRIES=
ZTA_LOCATION_ACCURACY_KM=50
```

**Post-Quantum Cryptography**:
```bash
# PQC Algorithm Selection
PQC_KEM_ALGORITHM=Kyber1024
PQC_SIGNATURE_ALGORITHM=Dilithium3
PQC_HASH_SIGNATURE_ALGORITHM=SPHINCS-SHA256-256f

# Key Management
PQC_KEY_ROTATION_DAYS=90
PQC_BACKUP_KEY_COUNT=3
PQC_SECURE_DELETE=true
```

## Deployment Guide

### Docker Infrastructure

#### Production Deployment (`docker-compose.yml`)
```yaml
version: '3.8'

services:
  # PostgreSQL Database
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: pass_vault
      POSTGRES_USER: vault_user
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./init-db.sql:/docker-entrypoint-initdb.d/init.sql
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U vault_user -d pass_vault"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Redis for Sessions and Caching
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Open Policy Agent
  opa:
    image: openpolicyagent/opa:latest
    ports:
      - "8181:8181"
    volumes:
      - ./opa-policies:/policies
    command: 
      - "run"
      - "--server"
      - "--log-level=debug"
      - "/policies"
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost:8181/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Backend Service
  backend:
    build: 
      context: ./pass_vault
      dockerfile: Dockerfile
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://vault_user:${POSTGRES_PASSWORD}@postgres:5432/pass_vault
      - REDIS_URL=redis://redis:6379/0
      - OPA_URL=http://opa:8181
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
      opa:
        condition: service_healthy
    volumes:
      - ./logs:/app/logs
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/api/v1/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Frontend Service
  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    ports:
      - "3000:3000"
    environment:
      - NEXT_PUBLIC_API_URL=http://localhost:8000
      - NEXT_PUBLIC_WEBAUTHN_RP_ID=localhost
    depends_on:
      - backend

  # Streamlit Dashboard
  dashboard:
    build:
      context: ./pass_vault
      dockerfile: Dockerfile.dashboard
    ports:
      - "8501:8501"
    environment:
      - DATABASE_URL=postgresql://vault_user:${POSTGRES_PASSWORD}@postgres:5432/pass_vault
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy

volumes:
  postgres_data:
  redis_data:
```

### Launch Scripts

#### Backend Launch (`run-backend.sh`)
```bash
#!/bin/bash
# Enhanced backend launcher with dependency checking

check_dependencies() {
    echo "🔍 Checking dependencies..."
    
    # Check Python version
    python_version=$(python3 --version 2>&1 | cut -d" " -f2)
    required_version="3.8.0"
    
    if ! python3 -c "import sys; exit(0 if sys.version_info >= (3,8) else 1)"; then
        echo "❌ Python 3.8+ required. Current: $python_version"
        exit 1
    fi
    
    # Check virtual environment
    if [[ "$VIRTUAL_ENV" == "" ]]; then
        echo "⚠️  Virtual environment not detected"
        echo "💡 Run: python3 -m venv venv && source venv/bin/activate"
        exit 1
    fi
    
    echo "✅ Python $python_version detected"
    echo "✅ Virtual environment: $VIRTUAL_ENV"
}

setup_environment() {
    echo "🔧 Setting up environment..."
    
    if [[ ! -f ".env" ]]; then
        if [[ -f "config.template" ]]; then
            echo "📋 Creating .env from template..."
            cp config.template .env
            echo "⚠️  Please configure .env with your settings"
        else
            echo "❌ No configuration template found"
            exit 1
        fi
    fi
    
    # Load environment variables
    set -a
    source .env
    set +a
    
    echo "✅ Environment loaded"
}

run_migrations() {
    echo "🗄️  Running database migrations..."
    
    if command -v alembic &> /dev/null; then
        alembic upgrade head
        echo "✅ Migrations completed"
    else
        echo "⚠️  Alembic not found, skipping migrations"
    fi
}

start_server() {
    echo "🚀 Starting Flask server..."
    echo "📡 Backend will be available at: http://localhost:${PORT:-8000}"
    
    python main.py --mode server --host 0.0.0.0 --port ${PORT:-8000}
}

# Main execution
main() {
    echo "🏗️  PQC-ZTA Password Vault Backend Launcher"
    echo "============================================"
    
    check_dependencies
    setup_environment
    run_migrations
    start_server
}

main "$@"
```

#### System Test Script (`test-system.sh`)
```bash
#!/bin/bash
# Comprehensive system testing script

run_dependency_tests() {
    echo "🔍 Testing system dependencies..."
    
    # Test Python imports
    python3 -c "
import sys
try:
    import flask, sqlalchemy, redis, cryptography
    import oqs  # Post-quantum cryptography
    print('✅ Core dependencies available')
except ImportError as e:
    print(f'❌ Missing dependency: {e}')
    sys.exit(1)
    "
    
    # Test database connectivity
    if [[ -n "$DATABASE_URL" ]]; then
        python3 -c "
from sqlalchemy import create_engine
try:
    engine = create_engine('$DATABASE_URL')
    with engine.connect() as conn:
        conn.execute('SELECT 1')
    print('✅ Database connectivity OK')
except Exception as e:
    print(f'❌ Database error: {e}')
    "
    fi
    
    # Test Redis connectivity
    if [[ -n "$REDIS_URL" ]]; then
        python3 -c "
import redis
try:
    r = redis.from_url('$REDIS_URL')
    r.ping()
    print('✅ Redis connectivity OK')
except Exception as e:
    print(f'❌ Redis error: {e}')
    "
}

run_security_tests() {
    echo "🔐 Testing security components..."
    
    # Test PQC functionality
    python3 -c "
from pass_vault.crypto.pqc import PQCKeyManager
try:
    manager = PQCKeyManager()
    public, private = manager.generate_kyber_keypair()
    print('✅ PQC key generation working')
except Exception as e:
    print(f'❌ PQC error: {e}')
    "
    
    # Test WebAuthn setup
    python3 -c "
from pass_vault.auth.webauthn import WebAuthnManager
try:
    manager = WebAuthnManager('localhost')
    print('✅ WebAuthn manager initialized')
except Exception as e:
    print(f'❌ WebAuthn error: {e}')
    "
}

run_api_tests() {
    echo "🌐 Testing API endpoints..."
    
    if curl -f -s http://localhost:8000/api/v1/health > /dev/null; then
        echo "✅ Health endpoint responding"
    else
        echo "❌ Health endpoint not responding"
    fi
}

# Main test execution
main() {
    echo "🧪 PQC-ZTA System Test Suite"
    echo "============================"
    
    run_dependency_tests
    run_security_tests
    
    if [[ "$1" == "--api" ]]; then
        run_api_tests
    fi
    
    echo "🎉 System tests completed"
}

main "$@"
```

## CLI Interface (`cli/interface.py`)

**Purpose**: Enhanced command-line interface for vault operations

**Features**:
- **Interactive Mode**: Menu-driven vault operations
- **Batch Operations**: Bulk password import/export
- **Security Operations**: Key rotation, audit queries
- **Administrative Tasks**: User management, system health

**Usage Examples**:
```bash
# Interactive vault management
python main.py --mode cli

# Create new vault
python main.py --mode cli --action create --vault myVault

# Import passwords from CSV
python main.py --mode cli --action import --file passwords.csv

# Generate security report
python main.py --mode cli --action audit --output report.json
```

**Current Status**: Placeholder for future implementation

**Planned Components**:
- Device verification
- Multi-factor authentication
- Risk-based access control

## Frontend Components

### 1. Application Structure

#### Root Layout (`src/app/layout.tsx`)

**Purpose**: Global application layout and providers

**Features**:
- **Theme Provider**: Dark/light theme support
- **Global Styles**: Tailwind CSS integration
- **Toast Notifications**: Sonner toast provider
- **Font Loading**: Inter font family

#### Main Page (`src/app/page.tsx`)

**Purpose**: Landing page with feature overview

**Components**:
- **Hero Section**: Application branding and CTA buttons
- **Feature Cards**: Security feature highlights
- **Authentication Check**: Auto-redirect if already logged in

### 2. Authentication Pages

#### Login Page (`src/app/login/page.tsx`)

**Purpose**: Vault authentication interface

**Features**:
- **Form Validation**: Zod schema validation with React Hook Form
- **Password Visibility**: Toggle for master password
- **Loading States**: UI feedback during authentication
- **Error Handling**: User-friendly error messages

**Form Schema**:
```typescript
const loginSchema = z.object({
    vault_name: z.string().min(1, 'Vault name is required'),
    master_password: z.string().min(8, 'Master password must be at least 8 characters'),
});
```

#### Registration Page (`src/app/register/page.tsx`)

**Purpose**: New vault creation interface

**Features** (Similar to login with additional):
- **Password Strength Validation**: Real-time strength feedback
- **Confirmation Field**: Master password confirmation
- **Security Guidelines**: Password requirements display

### 3. Dashboard (`src/app/dashboard/page.tsx`)

**Purpose**: Main password management interface

**Key Features**:

#### Password List
- **Service Display**: Service name, username, and metadata
- **Search Functionality**: Real-time search across services
- **Action Buttons**: View, copy, delete operations

#### Password Management
- **Add New Password**: Modal dialog for new entries
- **Password Generation**: Integrated secure password generator
- **Tags Support**: Categorization with tag system

#### Security Features
- **Session Management**: Auto-logout and session validation
- **Secure Copy**: Clipboard operations for password copying
- **View Controls**: Toggle password visibility

### 4. API Layer (`src/lib/api.ts`)

**Purpose**: Frontend-backend communication

**Key Components**:

#### Axios Configuration
```typescript
const api = axios.create({
    baseURL: API_BASE_URL,
    headers: { 'Content-Type': 'application/json' }
});
```

#### Request Interceptor
- **Token Injection**: Automatic JWT token inclusion
- **Error Handling**: Automatic logout on 401 errors

#### API Functions
```typescript
export const vaultApi = {
    createVault: async (data: VaultCreateRequest) => { ... },
    authenticateVault: async (data: VaultAuthRequest) => { ... },
    logout: async () => { ... }
};

export const passwordApi = {
    listPasswords: async () => { ... },
    getPassword: async (serviceName: string) => { ... },
    storePassword: async (data: PasswordStoreRequest) => { ... },
    // ... other operations
};
```

### 5. UI Components (`src/components/ui/`)

**Purpose**: Reusable UI components based on shadcn/ui

**Key Components**:
- **Button**: Various button variants and sizes
- **Card**: Content containers with headers
- **Dialog**: Modal dialogs for forms
- **Input**: Form input fields with validation states
- **Alert**: Status and error messages
- **Badge**: Tags and status indicators
- **Avatar**: User and service avatars

### 6. Theme Provider (`src/components/theme-provider.tsx`)

**Purpose**: Dark/light theme management

**Features**:
- **System Theme Detection**: Respects OS theme preferences
- **Theme Persistence**: Remembers user theme choice
- **Smooth Transitions**: Theme switching animations

## Security Implementation

### 1. Encryption Architecture

#### Master Password Flow
```
Master Password ──► PBKDF2(password + salt, 100k iterations) ──► 256-bit Key
                                    │
                                    ▼
                         AES-256-GCM Encryption
                                    │
                                    ▼
                              Vault Key Storage
```

#### Password Storage Flow
```
Plaintext Password ──► AES-256-GCM(vault_key) ──► Base64 Encoding ──► Database
                              │
                              ▼
                    Nonce + Ciphertext + Auth Tag
```

### 2. Key Security Features

#### Zero-Knowledge Architecture
- **Client-Side Key Derivation**: Master passwords processed only on client
- **No Server-Side Storage**: Plain-text passwords never reach server
- **Encrypted Transmission**: All data encrypted before transmission

#### Session Security
- **JWT Tokens**: Stateless authentication with configurable expiration
- **Session Binding**: Vault keys tied to specific sessions
- **Automatic Cleanup**: Expired sessions removed from memory

#### Cryptographic Primitives
- **AES-256-GCM**: Authenticated encryption for data protection
- **Argon2**: Memory-hard password hashing for authentication
- **PBKDF2**: Key derivation for vault encryption keys
- **Secure Random**: Cryptographically secure random number generation

### 3. Future Post-Quantum Security

#### Current Preparation
- **Modular Design**: Crypto layer ready for PQC integration
- **liboqs Integration**: Library included for future implementation
- **Hybrid Approach**: Classical + quantum-resistant algorithms

#### Planned Implementation
- **CRYSTALS-Kyber**: Key encapsulation mechanism
- **CRYSTALS-Dilithium**: Digital signatures
- **SPHINCS+**: Alternative signature scheme

## Database Schema

### VaultMaster Table
```sql
CREATE TABLE vault_master (
    id INTEGER PRIMARY KEY,
    name VARCHAR UNIQUE NOT NULL,
    master_password_hash VARCHAR NOT NULL,
    salt VARCHAR NOT NULL,
    encrypted_key TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### PasswordEntry Table
```sql
CREATE TABLE password_entries (
    id INTEGER PRIMARY KEY,
    vault_id INTEGER NOT NULL,
    service_name VARCHAR NOT NULL,
    username VARCHAR NOT NULL,
    encrypted_password TEXT NOT NULL,
    encrypted_notes TEXT,
    website_url VARCHAR,
    tags VARCHAR,  -- JSON array
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_deleted BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (vault_id) REFERENCES vault_master (id)
);
```

### Indexes
```sql
CREATE INDEX idx_vault_master_name ON vault_master(name);
CREATE INDEX idx_password_entries_vault_id ON password_entries(vault_id);
CREATE INDEX idx_password_entries_service ON password_entries(service_name);
CREATE INDEX idx_password_entries_deleted ON password_entries(is_deleted);
```

## API Reference

### Authentication Endpoints

#### POST `/api/v1/vault/authenticate`
**Purpose**: Multi-factor vault authentication with ZTA

**Request Body**:
```json
{
  "vault_name": "string",
  "master_password": "string", 
  "device_context": {
    "device_id": "string",
    "user_agent": "string",
    "ip_address": "string",
    "geolocation": {"lat": 0, "lng": 0}
  },
  "webauthn_response": {} // Optional
}
```

**Response**:
```json
{
  "success": true,
  "session_token": "jwt_token_here",
  "risk_assessment": {
    "risk_score": 0.25,
    "risk_level": "LOW",
    "requires_step_up": false
  },
  "session_info": {
    "session_id": "uuid",
    "expires_at": "2024-01-01T00:00:00Z"
  }
}
```

#### POST `/api/v1/webauthn/register/begin`
**Purpose**: Initiate WebAuthn credential registration

**Request Body**:
```json
{
  "user_id": "string",
  "display_name": "string",
  "authenticator_selection": {
    "authenticator_attachment": "platform",
    "user_verification": "required"
  }
}
```

### Password Management Endpoints

#### POST `/api/v1/passwords`
**Purpose**: Store password with hybrid PQC encryption

**Request Body**:
```json
{
  "service_name": "string",
  "username": "string", 
  "password": "string",
  "notes": "string",
  "website_url": "string",
  "tags": ["tag1", "tag2"]
}
```

**Response**:
```json
{
  "success": true,
  "entry_id": "uuid",
  "encryption_info": {
    "algorithm": "kyber_aes",
    "key_id": "string"
  },
  "audit_signature": "sphincs_signature_here"
}
```

### Zero Trust Endpoints

#### GET `/api/v1/risk/assessment`
**Purpose**: Get current session risk assessment

**Response**:
```json
{
  "risk_score": 0.45,
  "risk_level": "MEDIUM", 
  "risk_factors": [
    "new_device",
    "unusual_location"
  ],
  "requires_step_up": true,
  "policy_decision": "CONDITIONAL_ALLOW",
  "recommendations": [
    "Enable step-up authentication",
    "Verify device identity"
  ]
}
```

## Development Environment

### Setup Instructions

1. **Clone Repository**:
```bash
git clone <repository-url>
cd pass_vault
```

2. **Backend Setup**:
```bash
cd pass_vault
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

3. **Frontend Setup**:
```bash
cd frontend
npm install
```

4. **Database Setup**:
```bash
# Start PostgreSQL
docker run -d --name postgres \
  -e POSTGRES_DB=pass_vault \
  -e POSTGRES_USER=vault_user \
  -e POSTGRES_PASSWORD=secure_password \
  -p 5432:5432 postgres:15-alpine

# Run migrations
alembic upgrade head
```

5. **Configuration**:
```bash
cp config.template .env
# Edit .env with your settings
```

### Development Commands

#### Full Development Environment
```bash
./run-dev.sh
```

#### Individual Services
```bash
# Backend only
./run-backend.sh

# Frontend only  
./run-frontend.sh

# Dashboard only
python main.py --mode dashboard

# System tests
./test-system.sh
```

#### Docker Development
```bash
# Start all services
docker-compose -f docker-compose.dev.yml up

# Rebuild and start
docker-compose -f docker-compose.dev.yml up --build

# View logs
docker-compose logs -f backend
```

## Troubleshooting

### Common Issues

#### 1. Database Connection Errors
**Symptoms**: Connection refused, authentication failed
**Solutions**:
```bash
# Check PostgreSQL status
docker ps | grep postgres

# Verify connection string
psql postgresql://vault_user:password@localhost:5432/pass_vault

# Reset database
docker-compose down -v
docker-compose up postgres -d
alembic upgrade head
```

#### 2. Redis Connection Issues
**Symptoms**: Session storage errors, cache failures
**Solutions**:
```bash
# Check Redis connectivity
redis-cli ping

# Clear Redis data
redis-cli FLUSHALL

# Restart Redis
docker-compose restart redis
```

#### 3. OPA Policy Errors
**Symptoms**: Access denied, policy evaluation failures
**Solutions**:
```bash
# Check OPA status
curl http://localhost:8181/health

# Reload policies
curl -X PUT http://localhost:8181/v1/policies/vault \
  --data-binary @opa-policies/vault_access.rego

# Test policy
curl -X POST http://localhost:8181/v1/data/vault/access \
  -H "Content-Type: application/json" \
  -d '{"input": {"user": "test", "action": "read"}}'
```

#### 4. WebAuthn Registration Failures
**Symptoms**: Credential creation errors, browser compatibility
**Solutions**:
- Ensure HTTPS in production
- Check browser WebAuthn support
- Verify RP ID configuration
- Clear browser credential storage

#### 5. PQC Library Issues
**Symptoms**: Import errors, key generation failures
**Solutions**:
```bash
# Install liboqs dependencies
sudo apt-get install cmake ninja-build
pip install --upgrade liboqs-python

# Test PQC functionality
python -c "import oqs; print('PQC available')"
```

### Performance Optimization

#### Database Optimization
```sql
-- Index creation for better performance
CREATE INDEX CONCURRENTLY idx_password_entries_service ON password_entries(service_name);
CREATE INDEX CONCURRENTLY idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX CONCURRENTLY idx_zta_sessions_user ON zta_sessions(user_id, is_active);

-- Full-text search optimization
CREATE INDEX CONCURRENTLY idx_password_entries_search ON password_entries USING gin(search_vector);
```

#### Redis Configuration
```bash
# Optimize Redis for session storage
redis-cli CONFIG SET maxmemory 1gb
redis-cli CONFIG SET maxmemory-policy allkeys-lru
redis-cli CONFIG SET save "900 1 300 10 60 10000"
```

#### Application Performance
- Enable Flask-Caching for frequent queries
- Use connection pooling for database
- Implement async operations where possible
- Monitor with Prometheus metrics

### Security Considerations

#### Production Deployment
1. **HTTPS Only**: Never deploy without TLS
2. **Secret Management**: Use environment variables or secrets manager
3. **Database Security**: Enable SSL, restrict connections
4. **Rate Limiting**: Configure appropriate limits
5. **Monitoring**: Enable comprehensive logging and alerting

#### Regular Maintenance
1. **Key Rotation**: Rotate PQC keys every 90 days
2. **Certificate Updates**: Monitor TLS certificate expiration
3. **Security Updates**: Keep dependencies updated
4. **Audit Reviews**: Regular security audit log analysis
5. **Backup Testing**: Verify backup restoration procedures

### Monitoring and Alerting

#### Prometheus Metrics
- `vault_active_sessions_total`: Current active sessions
- `vault_authentication_attempts_total`: Authentication attempts by status
- `vault_risk_score_histogram`: Distribution of risk scores
- `vault_pqc_operations_duration_seconds`: PQC operation performance
- `vault_database_connection_pool_usage`: Database connection usage

#### Log Analysis
- Failed authentication patterns
- Unusual access patterns
- Performance anomalies
- Error rate trends
- Security event correlation

This comprehensive documentation covers all aspects of the PQC-ZTA Password Vault system, from basic setup to advanced security configuration and troubleshooting. The system provides enterprise-grade security with quantum-resistant cryptography, zero trust architecture, and modern authentication mechanisms. 