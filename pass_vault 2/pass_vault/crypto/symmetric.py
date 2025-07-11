from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import json

# It's common to store nonce, tag, and ciphertext together.
# We can define standard key sizes. AES supports 128, 192, or 256 bits.
AES_KEY_SIZE = 32  # 32 bytes = 256 bits

def generate_aes_key() -> bytes:
    """Generates a secure random AES key (256-bit)."""
    return get_random_bytes(AES_KEY_SIZE)

def encrypt_aes(key: bytes, plaintext_data: bytes) -> bytes:
    """
    Encrypts plaintext data using AES-GCM.
    Returns a JSON string containing nonce, ciphertext, and tag.
    This makes it easier to store/transmit all necessary components.
    """
    if not isinstance(key, bytes) or len(key) != AES_KEY_SIZE:
        raise ValueError(f"Key must be {AES_KEY_SIZE} bytes long.")
    if not isinstance(plaintext_data, bytes):
        raise ValueError("Plaintext data must be bytes.")

    cipher = AES.new(key, AES.MODE_GCM)  # Creates a new cipher object
    nonce = cipher.nonce  # Generate a random nonce
    ciphertext, tag = cipher.encrypt_and_digest(plaintext_data)

    # Store nonce, ciphertext, and tag together, typically encoded
    # For simplicity, returning as a JSON serialized dictionary of hex strings
    encrypted_package = {
        'nonce': nonce.hex(),
        'ciphertext': ciphertext.hex(),
        'tag': tag.hex()
    }
    return json.dumps(encrypted_package).encode('utf-8')

def decrypt_aes(key: bytes, encrypted_package_json: bytes) -> bytes:
    """
    Decrypts data using AES-GCM from a JSON package (nonce, ciphertext, tag).
    Returns the original plaintext data if decryption is successful.
    Raises ValueError or MACMismatchError on failure.
    """
    if not isinstance(key, bytes) or len(key) != AES_KEY_SIZE:
        raise ValueError(f"Key must be {AES_KEY_SIZE} bytes long.")
    if not isinstance(encrypted_package_json, bytes):
        raise ValueError("Encrypted package must be bytes.")

    try:
        package = json.loads(encrypted_package_json.decode('utf-8'))
        nonce = bytes.fromhex(package['nonce'])
        ciphertext = bytes.fromhex(package['ciphertext'])
        tag = bytes.fromhex(package['tag'])
    except (json.JSONDecodeError, KeyError, ValueError) as e:
        raise ValueError(f"Invalid encrypted package format: {e}")

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except ValueError as e: # Catches MAC check failed and other value errors
        # It's crucial to handle decryption errors properly to avoid padding oracle attacks,
        # though GCM is less susceptible than CBC mode.
        # Distinguishing between "MAC failed" and "malformed ciphertext" can be tricky
        # and often not recommended to reveal to the caller.
        raise ValueError(f"Decryption failed. Data may be corrupt or key incorrect: {e}")
