# Post-Quantum Cryptography Zero Trust Architecture Password Vault Storage
# Database models updated for PostgreSQL with full PQC and ZTA support

import json
import os
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean, LargeBinary, Float, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from sqlalchemy.dialects.postgresql import JSON, UUID
from passlib.context import CryptContext
from argon2 import PasswordHasher
from crypto.symmetric import generate_aes_key, encrypt_aes, decrypt_aes
from crypto.pqc import PQCKeyManager, PQCEncryption, PQCAuditLogger
import base64
import uuid
import structlog

# Configure logging
logger = structlog.get_logger(__name__)

Base = declarative_base()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
ph = PasswordHasher()

class VaultMaster(Base):
    """Master vault table with PQC key support."""
    __tablename__ = "vault_master"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, index=True)
    master_password_hash = Column(String(255))
    salt = Column(String(255))
    encrypted_key = Column(Text)  # Encrypted vault key using classical crypto
    
    # PQC Keys
    kyber_public_key = Column(Text)  # Base64 encoded Kyber public key
    kyber_private_key = Column(Text)  # Base64 encoded Kyber private key (encrypted)
    dilithium_public_key = Column(Text)  # Base64 encoded Dilithium public key
    dilithium_private_key = Column(Text)  # Base64 encoded Dilithium private key (encrypted)
    sphincs_public_key = Column(Text)  # Base64 encoded SPHINCS+ public key
    sphincs_private_key = Column(Text)  # Base64 encoded SPHINCS+ private key (encrypted)
    
    # Metadata
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    is_active = Column(Boolean, default=True)
    
    # Relationships
    password_entries = relationship("PasswordEntry", back_populates="vault")
    audit_entries = relationship("AuditEntry", back_populates="vault")
    user_sessions = relationship("UserSession", back_populates="vault")

class PasswordEntry(Base):
    """Password entries with PQC encryption."""
    __tablename__ = "password_entries"
    
    id = Column(Integer, primary_key=True, index=True)
    vault_id = Column(Integer, ForeignKey("vault_master.id"), index=True)
    service_name = Column(String(255), index=True)
    username = Column(String(255), index=True)
    
    # Classical encryption (AES-GCM)
    encrypted_password = Column(Text)
    encrypted_notes = Column(Text, nullable=True)
    
    # PQC encryption (Kyber + AES-GCM hybrid)
    pqc_encrypted_password = Column(Text, nullable=True)
    pqc_encrypted_notes = Column(Text, nullable=True)
    
    # Additional fields
    website_url = Column(String(500), nullable=True)
    tags = Column(JSON, nullable=True)  # JSON array of tags
    
    # Metadata
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    is_deleted = Column(Boolean, default=False)
    
    # Relationships
    vault = relationship("VaultMaster", back_populates="password_entries")
    audit_entries = relationship("AuditEntry", back_populates="password_entry")

class WebAuthnCredential(Base):
    """WebAuthn credentials for biometric authentication."""
    __tablename__ = "webauthn_credentials"
    
    id = Column(Integer, primary_key=True, index=True)
    credential_id = Column(String(255), unique=True, index=True)
    user_id = Column(String(255), index=True)
    public_key = Column(Text)
    counter = Column(Integer, default=0)
    authenticator_type = Column(String(50))  # 'platform' or 'cross-platform'
    
    # Metadata
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_used = Column(DateTime, nullable=True)
    usage_count = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    
    # Device information
    device_name = Column(String(255), nullable=True)
    device_id = Column(String(255), nullable=True)

class UserSession(Base):
    """User sessions with ZTA context."""
    __tablename__ = "user_sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(255), unique=True, index=True)
    user_id = Column(String(255), index=True)
    vault_id = Column(Integer, ForeignKey("vault_master.id"), index=True)
    
    # Session data
    encrypted_vault_key = Column(Text)  # Encrypted vault key for this session
    
    # ZTA context
    device_id = Column(String(255))
    ip_address = Column(String(45))  # IPv6 compatible
    user_agent = Column(String(500))
    geolocation = Column(JSON, nullable=True)
    risk_score = Column(Float, default=0.0)
    anomaly_score = Column(Float, default=0.0)
    
    # Session metadata
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_activity = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime)
    is_active = Column(Boolean, default=True)
    
    # Relationships
    vault = relationship("VaultMaster", back_populates="user_sessions")
    audit_entries = relationship("AuditEntry", back_populates="session")

class DeviceContext(Base):
    """Device context for ZTA evaluation."""
    __tablename__ = "device_contexts"
    
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String(255), unique=True, index=True)
    user_id = Column(String(255), index=True)
    
    # Device information
    device_fingerprint = Column(String(255), nullable=True)
    device_name = Column(String(255), nullable=True)
    device_type = Column(String(50), nullable=True)  # 'mobile', 'desktop', etc.
    
    # Trust information
    is_trusted = Column(Boolean, default=False)
    trust_score = Column(Float, default=0.0)
    
    # Location tracking
    last_known_location = Column(JSON, nullable=True)
    location_history = Column(JSON, nullable=True)
    
    # Metadata
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    is_active = Column(Boolean, default=True)

class AuditEntry(Base):
    """GDPR-compliant audit log with PQC signatures."""
    __tablename__ = "audit_entries"
    
    id = Column(Integer, primary_key=True, index=True)
    audit_id = Column(String(255), unique=True, index=True)
    
    # Audit information
    action = Column(String(255), index=True)
    user_id = Column(String(255), index=True)
    vault_id = Column(Integer, ForeignKey("vault_master.id"), nullable=True)
    password_entry_id = Column(Integer, ForeignKey("password_entries.id"), nullable=True)
    session_id = Column(String(255), ForeignKey("user_sessions.session_id"), nullable=True)
    
    # Context information
    context_data = Column(JSON, nullable=True)
    risk_score = Column(Float, nullable=True)
    device_id = Column(String(255), nullable=True)
    ip_address = Column(String(45), nullable=True)
    
    # PQC signature for integrity
    audit_signature = Column(Text)  # SPHINCS+ signature
    signature_algorithm = Column(String(50), default="SPHINCS+-SHA2-256f-simple")
    
    # Metadata
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Relationships
    vault = relationship("VaultMaster", back_populates="audit_entries")
    password_entry = relationship("PasswordEntry", back_populates="audit_entries")
    session = relationship("UserSession", back_populates="audit_entries")

class PolicyDecision(Base):
    """OPA policy decisions for ZTA."""
    __tablename__ = "policy_decisions"
    
    id = Column(Integer, primary_key=True, index=True)
    decision_id = Column(String(255), unique=True, index=True)
    
    # Decision context
    user_id = Column(String(255), index=True)
    action = Column(String(255), index=True)
    resource = Column(String(255), index=True)
    
    # Decision result
    decision = Column(String(50))  # 'allow', 'deny', 'step_up', 'monitor'
    risk_score = Column(Float)
    risk_level = Column(String(50))
    
    # Policy information
    policy_name = Column(String(255), nullable=True)
    policy_result = Column(JSON, nullable=True)
    
    # Metadata
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class EnhancedVaultManager:
    """Enhanced vault manager with PQC and ZTA support."""
    
    def __init__(self, db_url: str = None):
        """Initialize with PostgreSQL database."""
        if db_url is None:
            # Default PostgreSQL connection
            db_url = os.getenv(
                "DATABASE_URL", 
                "postgresql://vault_user:vault_password@localhost:5432/password_vault"
            )
        
        self.engine = create_engine(db_url)
        Base.metadata.create_all(bind=self.engine)
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        self.db: Session = SessionLocal()
        
        # Initialize PQC components
        self.pqc_key_manager = PQCKeyManager()
        self.pqc_encryption = PQCEncryption()
        self.pqc_audit_logger = PQCAuditLogger()
        
    def create_vault(self, vault_name: str, master_password: str, 
                    user_id: str, device_context: Dict[str, Any]) -> Dict[str, Any]:
        """Creates a new password vault with PQC key generation."""
        try:
            # Check if vault already exists
            existing_vault = self.db.query(VaultMaster).filter(VaultMaster.name == vault_name).first()
            if existing_vault:
                return {"success": False, "error": "Vault already exists"}
            
            # Generate salt and hash master password
            salt = os.urandom(32)
            master_hash = ph.hash(master_password + salt.hex())
            
            # Generate classical vault encryption key
            vault_key = generate_aes_key()
            
            # Derive deterministic encryption key using PBKDF2
            from Crypto.Protocol.KDF import PBKDF2
            from Crypto.Hash import SHA256
            key_for_encryption = PBKDF2(master_password, salt, 32, count=100000, hmac_hash_module=SHA256)
            encrypted_vault_key = encrypt_aes(key_for_encryption, vault_key)
            
            # Generate PQC key pairs
            kyber_public, kyber_private = self.pqc_key_manager.generate_kyber_keypair()
            dilithium_public, dilithium_private = self.pqc_key_manager.generate_dilithium_keypair()
            sphincs_public, sphincs_private = self.pqc_key_manager.generate_sphincs_keypair()
            
            # Encrypt PQC private keys with the master password key
            encrypted_kyber_private = encrypt_aes(key_for_encryption, kyber_private)
            encrypted_dilithium_private = encrypt_aes(key_for_encryption, dilithium_private)
            encrypted_sphincs_private = encrypt_aes(key_for_encryption, sphincs_private)
            
            # Create vault record
            vault = VaultMaster(
                name=vault_name,
                master_password_hash=master_hash,
                salt=salt.hex(),
                encrypted_key=base64.b64encode(encrypted_vault_key).decode(),
                kyber_public_key=base64.b64encode(kyber_public).decode(),
                kyber_private_key=base64.b64encode(encrypted_kyber_private).decode(),
                dilithium_public_key=base64.b64encode(dilithium_public).decode(),
                dilithium_private_key=base64.b64encode(encrypted_dilithium_private).decode(),
                sphincs_public_key=base64.b64encode(sphincs_public).decode(),
                sphincs_private_key=base64.b64encode(encrypted_sphincs_private).decode()
            )
            
            self.db.add(vault)
            self.db.commit()
            self.db.refresh(vault)
            
            # Create audit log entry
            audit_entry = self._create_audit_entry(
                action="vault_create",
                user_id=user_id,
                vault_id=vault.id,
                context_data=device_context,
                sphincs_private_key=sphincs_private
            )
            
            logger.info("PQC vault created successfully", 
                       vault_id=vault.id, 
                       user_id=user_id,
                       audit_id=audit_entry.audit_id)
            
            return {
                "success": True, 
                "vault_id": vault.id,
                "audit_id": audit_entry.audit_id,
                "message": f"PQC vault '{vault_name}' created successfully"
            }
            
        except Exception as e:
            self.db.rollback()
            logger.error("Failed to create PQC vault", error=str(e))
            return {"success": False, "error": str(e)}
    
    def authenticate_vault(self, vault_name: str, master_password: str, 
                          user_id: str, device_context: Dict[str, Any]) -> Dict[str, Any]:
        """Authenticates access to a vault with PQC support."""
        try:
            vault = self.db.query(VaultMaster).filter(VaultMaster.name == vault_name).first()
            if not vault:
                return {"success": False, "error": "Vault not found"}
            
            # Verify master password
            salt_hex = vault.salt
            
            try:
                ph.verify(vault.master_password_hash, master_password + salt_hex)
            except:
                # Create audit log for failed authentication
                self._create_audit_entry(
                    action="vault_auth_failed",
                    user_id=user_id,
                    vault_id=vault.id,
                    context_data=device_context,
                    sphincs_private_key=base64.b64decode(vault.sphincs_private_key)
                )
                return {"success": False, "error": "Invalid master password"}
            
            # Derive decryption key
            from Crypto.Protocol.KDF import PBKDF2
            from Crypto.Hash import SHA256
            salt_bytes = bytes.fromhex(salt_hex)
            key_for_decryption = PBKDF2(master_password, salt_bytes, 32, count=100000, hmac_hash_module=SHA256)
            
            # Decrypt vault key
            encrypted_vault_key = base64.b64decode(vault.encrypted_key)
            vault_key = decrypt_aes(key_for_decryption, encrypted_vault_key)
            
            # Decrypt PQC private keys
            kyber_private = decrypt_aes(key_for_decryption, base64.b64decode(vault.kyber_private_key))
            dilithium_private = decrypt_aes(key_for_decryption, base64.b64decode(vault.dilithium_private_key))
            sphincs_private = decrypt_aes(key_for_decryption, base64.b64decode(vault.sphincs_private_key))
            
            # Create audit log for successful authentication
            audit_entry = self._create_audit_entry(
                action="vault_auth_success",
                user_id=user_id,
                vault_id=vault.id,
                context_data=device_context,
                sphincs_private_key=sphincs_private
            )
            
            logger.info("PQC vault authenticated successfully", 
                       vault_id=vault.id, 
                       user_id=user_id,
                       audit_id=audit_entry.audit_id)
            
            return {
                "success": True,
                "vault_id": vault.id,
                "vault_key": vault_key,
                "pqc_keys": {
                    "kyber_public": base64.b64decode(vault.kyber_public_key),
                    "kyber_private": kyber_private,
                    "dilithium_public": base64.b64decode(vault.dilithium_public_key),
                    "dilithium_private": dilithium_private,
                    "sphincs_public": base64.b64decode(vault.sphincs_public_key),
                    "sphincs_private": sphincs_private
                },
                "audit_id": audit_entry.audit_id,
                "message": "Authentication successful"
            }
            
        except Exception as e:
            logger.error("Failed to authenticate PQC vault", error=str(e))
            return {"success": False, "error": str(e)}
    
    def store_password_pqc(self, vault_id: int, vault_key: bytes, kyber_public_key: bytes,
                          sphincs_private_key: bytes, user_id: str, service_name: str, 
                          username: str, password: str, notes: str = None, 
                          website_url: str = None, tags: List[str] = None,
                          device_context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Stores a password entry with PQC encryption."""
        try:
            # Classical encryption (backward compatibility)
            encrypted_password = encrypt_aes(vault_key, password.encode())
            encrypted_notes = encrypt_aes(vault_key, notes.encode()) if notes else None
            
            # PQC encryption
            pqc_encrypted_password = self.pqc_encryption.encrypt_hybrid(
                kyber_public_key, password.encode()
            )
            pqc_encrypted_notes = self.pqc_encryption.encrypt_hybrid(
                kyber_public_key, notes.encode()
            ) if notes else None
            
            # Create password entry
            entry = PasswordEntry(
                vault_id=vault_id,
                service_name=service_name,
                username=username,
                encrypted_password=base64.b64encode(encrypted_password).decode(),
                encrypted_notes=base64.b64encode(encrypted_notes).decode() if encrypted_notes else None,
                pqc_encrypted_password=base64.b64encode(json.dumps(pqc_encrypted_password).encode()).decode(),
                pqc_encrypted_notes=base64.b64encode(json.dumps(pqc_encrypted_notes).encode()).decode() if pqc_encrypted_notes else None,
                website_url=website_url,
                tags=tags
            )
            
            self.db.add(entry)
            self.db.commit()
            self.db.refresh(entry)
            
            # Create audit log entry
            audit_entry = self._create_audit_entry(
                action="password_store",
                user_id=user_id,
                vault_id=vault_id,
                password_entry_id=entry.id,
                context_data=device_context or {},
                sphincs_private_key=sphincs_private_key
            )
            
            logger.info("PQC password stored successfully", 
                       entry_id=entry.id, 
                       service_name=service_name,
                       audit_id=audit_entry.audit_id)
            
            return {
                "success": True,
                "entry_id": entry.id,
                "audit_id": audit_entry.audit_id,
                "message": f"Password stored for '{service_name}' with PQC encryption"
            }
            
        except Exception as e:
            self.db.rollback()
            logger.error("Failed to store PQC password", error=str(e))
            return {"success": False, "error": str(e)}
    
    def _create_audit_entry(self, action: str, user_id: str, vault_id: int = None,
                           password_entry_id: int = None, session_id: str = None,
                           context_data: Dict[str, Any] = None, 
                           sphincs_private_key: bytes = None) -> AuditEntry:
        """Create a cryptographically signed audit entry."""
        try:
            audit_id = str(uuid.uuid4())
            
            # Create audit entry without signature first
            audit_entry = AuditEntry(
                audit_id=audit_id,
                action=action,
                user_id=user_id,
                vault_id=vault_id,
                password_entry_id=password_entry_id,
                session_id=session_id,
                context_data=context_data or {},
                risk_score=context_data.get("risk_score", 0.0) if context_data else 0.0,
                device_id=context_data.get("device_id") if context_data else None,
                ip_address=context_data.get("ip_address") if context_data else None
            )
            
            # Create signature if SPHINCS+ private key is available
            if sphincs_private_key:
                audit_signature_data = self.pqc_audit_logger.create_audit_entry(
                    audit_private_key=sphincs_private_key,
                    action=action,
                    user_id=user_id,
                    resource=f"vault_{vault_id}" if vault_id else "system",
                    context=context_data or {}
                )
                audit_entry.audit_signature = audit_signature_data["signature"]
            
            self.db.add(audit_entry)
            self.db.commit()
            self.db.refresh(audit_entry)
            
            return audit_entry
            
        except Exception as e:
            logger.error("Failed to create audit entry", error=str(e))
            # Return entry without signature as fallback
            audit_entry = AuditEntry(
                audit_id=audit_id,
                action=action,
                user_id=user_id,
                vault_id=vault_id,
                password_entry_id=password_entry_id,
                session_id=session_id,
                context_data=context_data or {}
            )
            self.db.add(audit_entry)
            self.db.commit()
            self.db.refresh(audit_entry)
            return audit_entry
    
    def close(self):
        """Close database connection."""
        self.db.close()

# Legacy wrapper for backward compatibility
class VaultManager(EnhancedVaultManager):
    """Legacy vault manager wrapper."""
    
    def __init__(self, db_path: str = "vault.db"):
        """Initialize with SQLite for backward compatibility."""
        super().__init__(f"sqlite:///{db_path}")

# Export classes
__all__ = [
    "EnhancedVaultManager",
    "VaultManager",
    "VaultMaster",
    "PasswordEntry",
    "WebAuthnCredential",
    "UserSession",
    "DeviceContext",
    "AuditEntry",
    "PolicyDecision"
]
