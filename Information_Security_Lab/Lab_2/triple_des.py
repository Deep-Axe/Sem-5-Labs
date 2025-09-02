"""Triple DES (3DES) ECB demo with simple CLI.

Notes:
- 3DES keys must be 16 or 24 bytes long and have proper odd parity per byte.
- This script accepts any-length string key, normalizes it to 16/24 bytes by
  padding/truncation, and adjusts parity so the library accepts it.
- ECB mode is used here to match the lab style, but it's not semantically secure.
  Prefer CBC/GCM for real applications.
"""

import binascii
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad


def _normalize_3des_key(key: str) -> tuple[str, bytes]:
    """Normalize a string key to a valid 3DES key.

    - If length < 16, pad to 16 chars. If 16 < len < 24, pad to 24 chars.
    - If length > 24, truncate to 24 chars.
    - Encode as UTF-8 and fix parity with DES3.adjust_key_parity.

    Returns (actual_key_str, key_bytes_with_parity).
    """
    # Normalize to 16 or 24 characters
    if len(key) < 16:
        actual_key = key.ljust(16, '0')
    elif 16 < len(key) < 24:
        actual_key = key.ljust(24, '0')
    elif len(key) > 24:
        actual_key = key[:24]
    else:
        actual_key = key

    # Convert to bytes and enforce odd parity per byte as required by DES
    key_bytes = actual_key.encode('utf-8')
    key_bytes = DES3.adjust_key_parity(key_bytes)
    return actual_key, key_bytes


def encrypt_3des(message, key):
    try:
        # Normalize key to valid 3DES key material
        _, key_bytes = _normalize_3des_key(key)
        message_bytes = message.encode('utf-8')
        # ECB mode for demonstration (no IV); not recommended for real data
        cipher = DES3.new(key_bytes, DES3.MODE_ECB)
        padded_message = pad(message_bytes, DES3.block_size)
        ciphertext = cipher.encrypt(padded_message)
        ciphertext_hex = binascii.hexlify(ciphertext).decode('utf-8').upper()

        return ciphertext_hex

    except Exception as e:
        return f"Encryption failed: {str(e)}"


def decrypt_3des(ciphertext_hex, key):
    try:
        # Normalize key to valid 3DES key material
        _, key_bytes = _normalize_3des_key(key)
        ciphertext = binascii.unhexlify(ciphertext_hex)
        cipher = DES3.new(key_bytes, DES3.MODE_ECB)
        decrypted_padded = cipher.decrypt(ciphertext)
        decrypted_message = unpad(decrypted_padded, DES3.block_size).decode('utf-8')
        return decrypted_message
    except Exception as e:
        return f"Decryption failed: {str(e)}"

def validate_3des_key(key):
    """Lightweight validation for demo purposes (length and trivial repetition)."""
    if len(key) < 16:
        return False, "Key too short. Minimum 16 characters required for 3DES."

    if len(set(key[:8])) == 1 or len(set(key[8:16])) == 1:
        return False, "Weak key detected. Avoid using same character repeatedly."

    return True, "Key is valid."

def main():
    print("Triple DES Encryption/Decryption System")

    print()

    while True:
        choice = input("Enter encrypt or decrypt using 3DES cipher or exit out of prg: ")

        if choice == "encrypt":
            message = input("Enter plain text: ")
            key = input("Enter key (24 characters recommended): ")

            is_valid, validation_msg = validate_3des_key(key)
            if not is_valid:
                print("Key validation:", validation_msg)
                print("Using padded/truncated key for demonstration.")

            # Show and use the normalized key (after padding/truncation)
            actual_key, _ = _normalize_3des_key(key)
            result = encrypt_3des(message, actual_key)

            print("Key used:", actual_key)
            print("Key length:", len(actual_key), "characters (", len(actual_key) * 8, "bits )")

        elif choice == "decrypt":
            ciphertext_hex = input("Enter ciphertext (in hex): ")
            key = input("Enter key (24 characters): ")

            is_valid, validation_msg = validate_3des_key(key)
            if not is_valid:
                print("Key validation:", validation_msg)

            # Show and use the normalized key (after padding/truncation)
            actual_key, _ = _normalize_3des_key(key)
            result = decrypt_3des(ciphertext_hex, actual_key)

            print("Key used:", actual_key)
            print("Key length:", len(actual_key), "characters (", len(actual_key) * 8, "bits )")


        elif choice == "exit":
            break

        else:
            print("Invalid choice")
            continue

        if choice in ["encrypt", "decrypt"]:
            print("Resultant encryption/decryption is:", result)
        print()


if __name__ == '__main__':
    main()