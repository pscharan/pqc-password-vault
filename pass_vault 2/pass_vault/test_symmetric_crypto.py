from crypto.symmetric import generate_aes_key, encrypt_aes, decrypt_aes
import json # Added import for json

def run_test():
    print("Running symmetric crypto test...")
    # Test key generation
    key = generate_aes_key()
    print(f"Generated AES key: {key.hex()}")
    assert len(key) == 32, "Key length is incorrect"

    # Test encryption and decryption
    original_plaintext = b"This is some secret data!"
    print(f"Original plaintext: {original_plaintext.decode()}")

    encrypted_package = encrypt_aes(key, original_plaintext)
    print(f"Encrypted package: {encrypted_package.decode()}")

    decrypted_plaintext = decrypt_aes(key, encrypted_package)
    print(f"Decrypted plaintext: {decrypted_plaintext.decode()}")

    assert original_plaintext == decrypted_plaintext, "Decryption failed: Plaintext does not match original"
    print("AES Encryption and Decryption test successful!")

    # Test with wrong key
    wrong_key = generate_aes_key()
    try:
        decrypt_aes(wrong_key, encrypted_package)
        print("ERROR: Decryption with wrong key succeeded, but should have failed.")
        assert False, "Decryption with wrong key succeeded"
    except ValueError as e:
        print(f"Successfully caught error for wrong key decryption: {e}")
        assert "Decryption failed" in str(e), "Error message for wrong key is not as expected."

    # Test with tampered ciphertext
    # This part was referencing encrypted_package_json which is not defined in this scope.
    # It should refer to 'encrypted_package' which holds the JSON bytes.
    try:
        package = json.loads(encrypted_package.decode('utf-8')) # Corrected variable name
        tampered_ciphertext_hex = list(package['ciphertext'])
        # Ensure there's something to tamper, and it's not empty
        if tampered_ciphertext_hex:
            tampered_ciphertext_hex[0] = 'F' if tampered_ciphertext_hex[0] != 'F' else 'A' # Flip a hex char
        else: # Handle case of empty ciphertext, though unlikely with GCM unless plaintext is empty
            package['ciphertext'] = '00' # Add some invalid data if it was empty

        package['ciphertext'] = "".join(tampered_ciphertext_hex)
        tampered_package = json.dumps(package).encode('utf-8')
        decrypt_aes(key, tampered_package)
        print("ERROR: Decryption with tampered ciphertext succeeded, but should have failed.")
        assert False, "Decryption with tampered ciphertext succeeded"
    except ValueError as e:
        print(f"Successfully caught error for tampered ciphertext: {e}")
        assert "Decryption failed" in str(e), "Error message for tampered ciphertext is not as expected."

    print("All symmetric crypto tests passed!")

if __name__ == "__main__":
    run_test()
