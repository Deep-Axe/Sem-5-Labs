"""AES-128 CBC encryption/decryption helper with a simple CLI.

Details/assumptions:
- Key can be provided either as 32 hex characters (representing 16 bytes) or as a
  raw string that will be padded/truncated to 16 bytes (UTF-8) for AES-128.
- A random 16-byte IV is generated for every encryption (CBC mode). The output is
  IV || ciphertext, hex-encoded in uppercase. Decrypt requires the same key and
  extracts IV from the first 16 bytes of the input.
- PKCS7 padding is applied for encryption and removed for decryption.
- This sample does not provide authenticity (no MAC/AEAD). Use an authenticated
  mode (e.g., GCM/EAX) for integrity/confidentiality in real systems.
"""

import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

def encrypt_aes(message, key):
    """Encrypt a UTF-8 message using AES-128-CBC with PKCS7 padding.

    Args:
        message (str): Plaintext to encrypt.
        key (str): Either 32 hex chars (16 bytes) or an arbitrary string that
            will be padded/truncated to 16 bytes (UTF-8).

    Returns:
        str: Uppercase hex string of IV||ciphertext on success, or an error string.
    """
    try:
        # Normalize key to 16 bytes:
        # - If key length is 32, interpret as hex (16 bytes).
        # - Else, treat as UTF-8 string and pad/truncate to 16 chars (16 bytes).
        if len(key) == 32:
            key_bytes = binascii.unhexlify(key)
        else:
            if len(key) < 16:
                key = key.ljust(16, '0')
            elif len(key) > 16:
                key = key[:16]
            key_bytes = key.encode('utf-8')

        # Encode plaintext to bytes
        message_bytes = message.encode('utf-8')

        # Generate a random 16-byte IV for CBC mode; different every encryption
        iv = os.urandom(16)

        # Create AES cipher in CBC mode with the given key and IV
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)

        # PKCS7 pad to block size, then encrypt
        padded_message = pad(message_bytes, AES.block_size)
        ciphertext = cipher.encrypt(padded_message)

        # Prepend IV to ciphertext and return hex-encoded string
        encrypted_data = iv + ciphertext
        ciphertext_hex = binascii.hexlify(encrypted_data).decode('utf-8').upper()

        return ciphertext_hex

    except Exception as e:
        # Return a simple error string (instead of raising) for the CLI flow
        return f"Encryption failed: {str(e)}"


def decrypt_aes(ciphertext_hex, key):
    """Decrypt an AES-128-CBC message given as IV||ciphertext in hex.

    Args:
        ciphertext_hex (str): Uppercase/lowercase hex string of IV||ciphertext.
        key (str): Either 32 hex chars (16 bytes) or a string that will be
            padded/truncated to 16 bytes (UTF-8).

    Returns:
        str: Decrypted UTF-8 plaintext on success, or an error string.
    """
    try:
        # Normalize key as in encryption
        if len(key) == 32:
            key_bytes = binascii.unhexlify(key)
        else:
            if len(key) < 16:
                key = key.ljust(16, '0')
            elif len(key) > 16:
                key = key[:16]
            key_bytes = key.encode('utf-8')

        # Parse hex into bytes: first 16 bytes are IV, rest is ciphertext
        encrypted_data = binascii.unhexlify(ciphertext_hex)

        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        # Create cipher and decrypt, then remove PKCS7 padding
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)

        decrypted_padded = cipher.decrypt(ciphertext)
        decrypted_message = unpad(decrypted_padded, AES.block_size).decode('utf-8')

        return decrypted_message

    except Exception as e:
        # Common failures: invalid hex, wrong key/IV causing bad padding, etc.
        return f"Decryption failed: {str(e)}"

def main():
    """Simple REPL for AES-128-CBC encrypt/decrypt demo."""

    print("Key should be 32 hex characters for AES-128")
    print()

    while True:
        choice = input("Enter encrypt or decrypt using AES-128 cipher or exit out of prg: ")

        if choice == "encrypt":
            message = input("Enter plain text: ")
            key = input("Enter key (32 hex chars or 16 string chars): ")
            result = encrypt_aes(message, key)

            # Echo back the normalized key used (string and hex forms) for clarity
            if len(key) == 32:
                print("Key used (hex):", key)
            else:
                actual_key = key.ljust(16, '0') if len(key) < 16 else key[:16]
                print("Key used (string):", actual_key)
                print("Key used (hex):", binascii.hexlify(actual_key.encode()).decode().upper())

        elif choice == "decrypt":
            ciphertext_hex = input("Enter ciphertext (in hex): ")
            key = input("Enter key (32 hex chars or 16 string chars): ")
            result = decrypt_aes(ciphertext_hex, key)

            # Echo back normalized key used for decryption
            if len(key) == 32:
                print("Key used (hex):", key)
            else:
                actual_key = key.ljust(16, '0') if len(key) < 16 else key[:16]
                print("Key used (string):", actual_key)
                print("Key used (hex):", binascii.hexlify(actual_key.encode()).decode().upper())

        elif choice == "exit":
            break

        else:
            print("Invalid choice")
            continue

        print("Resultant encryption/decryption is:", result)
        print()


if __name__ == '__main__':
    main()