import os
import hashlib
import hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64


def generate_ecc_keys():
    try:
        print("Generating ECC key pair (P-256 curve)...")

        # Generate private key
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

        # Get public key
        public_key = private_key.public_key()

        return public_key, private_key

    except Exception as e:
        return None, None


def ecc_encrypt(message, public_key):
    try:
        ephemeral_private = ec.generate_private_key(ec.SECP256R1(), default_backend())
        ephemeral_public = ephemeral_private.public_key()

        shared_key = ephemeral_private.exchange(ec.ECDH(), public_key)

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=b'ECC-Encryption',
            backend=default_backend()
        ).derive(shared_key)

        aes_key = derived_key[:32]
        mac_key = derived_key[32:]

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        message_bytes = message.encode('utf-8')
        padding_length = 16 - (len(message_bytes) % 16)
        padded_message = message_bytes + bytes([padding_length] * padding_length)

        ciphertext = encryptor.update(padded_message) + encryptor.finalize()

        ephemeral_public_bytes = ephemeral_public.public_numbers().x.to_bytes(32, 'big') + \
                                 ephemeral_public.public_numbers().y.to_bytes(32, 'big')

        mac_data = ephemeral_public_bytes + iv + ciphertext
        mac = hmac.new(mac_key, mac_data, hashlib.sha256).digest()

        encrypted_data = ephemeral_public_bytes + iv + ciphertext + mac

        return base64.b64encode(encrypted_data).decode('utf-8')

    except Exception as e:
        return f"Encryption failed: {str(e)}"


def ecc_decrypt(encrypted_data_b64, private_key):
    try:
        encrypted_data = base64.b64decode(encrypted_data_b64.encode('utf-8'))

        ephemeral_public_bytes = encrypted_data[:64]
        iv = encrypted_data[64:80]  # 16 bytes
        ciphertext = encrypted_data[80:-32]
        received_mac = encrypted_data[-32:]
        x = int.from_bytes(ephemeral_public_bytes[:32], 'big')
        y = int.from_bytes(ephemeral_public_bytes[32:], 'big')
        ephemeral_public_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
        ephemeral_public = ephemeral_public_numbers.public_key(default_backend())

        shared_key = private_key.exchange(ec.ECDH(), ephemeral_public)

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=b'ECC-Encryption',
            backend=default_backend()
        ).derive(shared_key)

        aes_key = derived_key[:32]
        mac_key = derived_key[32:]

        mac_data = ephemeral_public_bytes + iv + ciphertext
        expected_mac = hmac.new(mac_key, mac_data, hashlib.sha256).digest()

        if not hmac.compare_digest(received_mac, expected_mac):
            return "Decryption failed: MAC verification failed"

        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        padding_length = padded_plaintext[-1]
        plaintext = padded_plaintext[:-padding_length]

        return plaintext.decode('utf-8')

    except Exception as e:
        return f"Decryption failed: {str(e)}"


def display_keys(public_key, private_key):
    if not public_key or not private_key:
        print("No keys available.")
        return

    public_numbers = public_key.public_numbers()
    x = public_numbers.x
    y = public_numbers.y

    private_numbers = private_key.private_numbers()
    private_value = private_numbers.private_value

    print("ECC Key Information (P-256 Curve):")
    print(f"Curve: SECP256R1 (P-256)")
    print(f"Key size: 256 bits")
    print()
    print("Public Key (x, y coordinates):")
    print(f"x = {x}")
    print(f"y = {y}")
    print()
    print("Private Key:")
    print(f"d = {private_value}")


def main():

    result = ''

    public_key = None
    private_key = None

    while True:
        choice = input("Enter generate, encrypt or decrypt using ECC cipher or exit out of prg: ")

        if choice == "generate":
            print("Generating ECC key pair (P-256 curve)...")
            public_key, private_key = generate_ecc_keys()
            if public_key and private_key:
                print("ECC keys generated successfully!")
                display_keys(public_key, private_key)
            else:
                print("Key generation failed!")

        elif choice == "encrypt":
            if not public_key:
                print("No keys available. Please generate keys first.")
                continue

            message = input("Enter plain text: ")
            result = ecc_encrypt(message, public_key)

            if public_key:
                public_numbers = public_key.public_numbers()
                print(f"Public key used: ({public_numbers.x}, {public_numbers.y})")

        elif choice == "decrypt":
            if not private_key:
                print("No keys available. Please generate keys first.")
                continue

            ciphertext_b64 = input("Enter ciphertext (base64): ")
            result = ecc_decrypt(ciphertext_b64, private_key)

            if private_key:
                private_numbers = private_key.private_numbers()
                print(f"Private key used: {private_numbers.private_value}")

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
