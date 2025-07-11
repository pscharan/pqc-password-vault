# Post-Quantum Cryptography Implementation
# Using NIST-approved algorithms: Kyber-1024 (Level 5) and Dilithium-III (Level 3)

import oqs
import secrets
import json
import base64
from typing import Dict, Tuple, Optional, Any
from datetime import datetime, timezone
import hashlib
import hmac

# PQC Algorithm Configuration
KYBER_ALG = "Kyber1024"  # NIST Level 5 security
DILITHIUM_ALG = "Dilithium3"  # NIST Level 3 security
SPHINCS_ALG = "SPHINCS+-SHA2-256f-simple"  # For acknowledgment signatures

class PQCKeyManager:
    """Manages Post-Quantum Cryptography key operations."""
    
    def __init__(self):
        self.kyber_kem = oqs.KeyEncapsulation(KYBER_ALG)
        self.dilithium_sig = oqs.Signature(DILITHIUM_ALG)
        self.sphincs_sig = oqs.Signature(SPHINCS_ALG)
    
    def generate_kyber_keypair(self) -> Tuple[bytes, bytes]:
        """Generate Kyber-1024 key pair for key encapsulation."""
        try:
            public_key = self.kyber_kem.generate_keypair()
            private_key = self.kyber_kem.export_secret_key()
            return public_key, private_key
        except Exception as e:
            raise RuntimeError(f"Failed to generate Kyber keypair: {e}")
    
    def generate_dilithium_keypair(self) -> Tuple[bytes, bytes]:
        """Generate Dilithium-III key pair for digital signatures."""
        try:
            public_key = self.dilithium_sig.generate_keypair()
            private_key = self.dilithium_sig.export_secret_key()
            return public_key, private_key
        except Exception as e:
            raise RuntimeError(f"Failed to generate Dilithium keypair: {e}")
    
    def generate_sphincs_keypair(self) -> Tuple[bytes, bytes]:
        """Generate SPHINCS+ key pair for acknowledgment signatures."""
        try:
            public_key = self.sphincs_sig.generate_keypair()
            private_key = self.sphincs_sig.export_secret_key()
            return public_key, private_key
        except Exception as e:
            raise RuntimeError(f"Failed to generate SPHINCS+ keypair: {e}")

class PQCEncryption:
    """Handles PQC encryption operations using Kyber + AES-GCM hybrid approach."""
    
    def __init__(self):
        self.kyber_kem = oqs.KeyEncapsulation(KYBER_ALG)
    
    def encrypt_hybrid(self, recipient_public_key: bytes, plaintext: bytes) -> Dict[str, str]:
        """
        Encrypt data using Kyber + AES-GCM hybrid encryption.
        
        Args:
            recipient_public_key: Kyber public key of recipient
            plaintext: Data to encrypt
            
        Returns:
            Dictionary containing encrypted data components
        """
        try:
            # Generate ephemeral key pair
            ephemeral_public_key = self.kyber_kem.generate_keypair()
            
            # Encapsulate secret using recipient's public key
            ciphertext, shared_secret = self.kyber_kem.encap_secret(recipient_public_key)
            
            # Derive AES key from shared secret
            aes_key = hashlib.sha256(shared_secret).digest()
            
            # Encrypt plaintext with AES-GCM
            from crypto.symmetric import encrypt_aes
            encrypted_data = encrypt_aes(aes_key, plaintext)
            
            # Package all components
            package = {
                "ephemeral_public_key": base64.b64encode(ephemeral_public_key).decode(),
                "kyber_ciphertext": base64.b64encode(ciphertext).decode(),
                "aes_encrypted_data": base64.b64encode(encrypted_data).decode(),
                "algorithm": KYBER_ALG,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
            return package
            
        except Exception as e:
            raise RuntimeError(f"Hybrid encryption failed: {e}")
    
    def decrypt_hybrid(self, private_key: bytes, encrypted_package: Dict[str, str]) -> bytes:
        """
        Decrypt data using Kyber + AES-GCM hybrid decryption.
        
        Args:
            private_key: Kyber private key
            encrypted_package: Dictionary containing encrypted components
            
        Returns:
            Decrypted plaintext data
        """
        try:
            # Extract components
            kyber_ciphertext = base64.b64decode(encrypted_package["kyber_ciphertext"])
            aes_encrypted_data = base64.b64decode(encrypted_package["aes_encrypted_data"])
            
            # Decapsulate shared secret
            shared_secret = self.kyber_kem.decap_secret(kyber_ciphertext)
            
            # Derive AES key from shared secret
            aes_key = hashlib.sha256(shared_secret).digest()
            
            # Decrypt with AES-GCM
            from crypto.symmetric import decrypt_aes
            plaintext = decrypt_aes(aes_key, aes_encrypted_data)
            
            return plaintext
            
        except Exception as e:
            raise RuntimeError(f"Hybrid decryption failed: {e}")

class PQCSignature:
    """Handles PQC digital signature operations."""
    
    def __init__(self):
        self.dilithium_sig = oqs.Signature(DILITHIUM_ALG)
        self.sphincs_sig = oqs.Signature(SPHINCS_ALG)
    
    def sign_dilithium(self, private_key: bytes, message: bytes) -> bytes:
        """Sign message using Dilithium-III for device attestation."""
        try:
            # Import private key
            self.dilithium_sig.set_secret_key(private_key)
            
            # Sign the message
            signature = self.dilithium_sig.sign(message)
            return signature
            
        except Exception as e:
            raise RuntimeError(f"Dilithium signing failed: {e}")
    
    def verify_dilithium(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify Dilithium-III signature."""
        try:
            # Import public key
            self.dilithium_sig.set_public_key(public_key)
            
            # Verify signature
            return self.dilithium_sig.verify(message, signature, public_key)
            
        except Exception as e:
            return False
    
    def sign_sphincs(self, private_key: bytes, message: bytes) -> bytes:
        """Sign message using SPHINCS+ for acknowledgment signatures."""
        try:
            # Import private key
            self.sphincs_sig.set_secret_key(private_key)
            
            # Sign the message
            signature = self.sphincs_sig.sign(message)
            return signature
            
        except Exception as e:
            raise RuntimeError(f"SPHINCS+ signing failed: {e}")
    
    def verify_sphincs(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify SPHINCS+ signature."""
        try:
            # Import public key
            self.sphincs_sig.set_public_key(public_key)
            
            # Verify signature
            return self.sphincs_sig.verify(message, signature, public_key)
            
        except Exception as e:
            return False

class PQCDeviceAttestation:
    """Handles device attestation using Dilithium signatures."""
    
    def __init__(self):
        self.signature_handler = PQCSignature()
    
    def create_device_attestation(self, device_private_key: bytes, 
                                 context: Dict[str, Any]) -> Dict[str, str]:
        """
        Create device attestation using Dilithium signatures.
        
        Args:
            device_private_key: Device's Dilithium private key
            context: Device context (IP, user agent, timestamp, etc.)
            
        Returns:
            Attestation package with signature
        """
        try:
            # Create attestation payload
            attestation_data = {
                "device_id": context.get("device_id", "unknown"),
                "ip_address": context.get("ip_address", "unknown"),
                "user_agent": context.get("user_agent", "unknown"),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "location": context.get("location", "unknown"),
                "risk_score": context.get("risk_score", 0.0)
            }
            
            # Serialize and sign
            payload = json.dumps(attestation_data, sort_keys=True).encode()
            signature = self.signature_handler.sign_dilithium(device_private_key, payload)
            
            return {
                "attestation_data": base64.b64encode(payload).decode(),
                "signature": base64.b64encode(signature).decode(),
                "algorithm": DILITHIUM_ALG,
                "created_at": attestation_data["timestamp"]
            }
            
        except Exception as e:
            raise RuntimeError(f"Device attestation failed: {e}")
    
    def verify_device_attestation(self, device_public_key: bytes, 
                                 attestation_package: Dict[str, str]) -> bool:
        """Verify device attestation signature."""
        try:
            # Extract components
            payload = base64.b64decode(attestation_package["attestation_data"])
            signature = base64.b64decode(attestation_package["signature"])
            
            # Verify signature
            return self.signature_handler.verify_dilithium(device_public_key, payload, signature)
            
        except Exception as e:
            return False

class PQCAuditLogger:
    """Handles cryptographic audit logging for GDPR compliance."""
    
    def __init__(self):
        self.signature_handler = PQCSignature()
    
    def create_audit_entry(self, audit_private_key: bytes, 
                          action: str, user_id: str, 
                          resource: str, context: Dict[str, Any]) -> Dict[str, str]:
        """
        Create cryptographically signed audit entry.
        
        Args:
            audit_private_key: SPHINCS+ private key for audit signing
            action: Action performed (e.g., "password_access", "vault_create")
            user_id: User identifier
            resource: Resource accessed
            context: Additional context data
            
        Returns:
            Signed audit entry
        """
        try:
            # Create audit data
            audit_data = {
                "action": action,
                "user_id": user_id,
                "resource": resource,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "context": context,
                "audit_id": secrets.token_hex(16)
            }
            
            # Serialize and sign
            payload = json.dumps(audit_data, sort_keys=True).encode()
            signature = self.signature_handler.sign_sphincs(audit_private_key, payload)
            
            return {
                "audit_data": base64.b64encode(payload).decode(),
                "signature": base64.b64encode(signature).decode(),
                "algorithm": SPHINCS_ALG,
                "audit_id": audit_data["audit_id"],
                "timestamp": audit_data["timestamp"]
            }
            
        except Exception as e:
            raise RuntimeError(f"Audit logging failed: {e}")
    
    def verify_audit_entry(self, audit_public_key: bytes, 
                          audit_entry: Dict[str, str]) -> bool:
        """Verify audit entry signature."""
        try:
            # Extract components
            payload = base64.b64decode(audit_entry["audit_data"])
            signature = base64.b64decode(audit_entry["signature"])
            
            # Verify signature
            return self.signature_handler.verify_sphincs(audit_public_key, payload, signature)
            
        except Exception as e:
            return False

# Legacy function wrappers for backward compatibility
def generate_keys() -> Tuple[bytes, bytes]:
    """Generate Kyber-1024 key pair (legacy wrapper)."""
    key_manager = PQCKeyManager()
    return key_manager.generate_kyber_keypair()

def encrypt(public_key: bytes, plaintext: bytes) -> Dict[str, str]:
    """Encrypt using hybrid PQC approach (legacy wrapper)."""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()
    
    encryption = PQCEncryption()
    return encryption.encrypt_hybrid(public_key, plaintext)

def decrypt(private_key: bytes, ciphertext: Dict[str, str]) -> bytes:
    """Decrypt using hybrid PQC approach (legacy wrapper)."""
    encryption = PQCEncryption()
    return encryption.decrypt_hybrid(private_key, ciphertext)

# Export main classes
__all__ = [
    "PQCKeyManager",
    "PQCEncryption", 
    "PQCSignature",
    "PQCDeviceAttestation",
    "PQCAuditLogger",
    "generate_keys",
    "encrypt",
    "decrypt"
]
