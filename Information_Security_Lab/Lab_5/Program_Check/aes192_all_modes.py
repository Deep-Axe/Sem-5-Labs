"""Demonstrate AES-192 in multiple modes: ECB, CBC, CFB, OFB, CTR, GCM."""
from Crypto.Cipher import AES
import os


def print_hex(label, data: bytes):
    print(f"{label}: {data.hex()}")


def run_demo():
    print('=== AES-192 All Modes Demo ===')
    key = b'B' * 24  # 24 bytes -> AES-192
    pt = b'ExamplePlainText'[:16]
    print_hex('Key', key)
    print_hex('Plaintext', pt)
    print()

    # ECB
    print('-- ECB --')
    cipher = AES.new(key, AES.MODE_ECB)
    ct = cipher.encrypt(pt)
    dec = AES.new(key, AES.MODE_ECB).decrypt(ct)
    print_hex('Ciphertext', ct)
    print_hex('Decrypted', dec)
    print()

    # CBC
    print('-- CBC --')
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ct = cipher.encrypt(pt)
    dec = AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ct)
    print_hex('IV', iv)
    print_hex('Ciphertext', ct)
    print_hex('Decrypted', dec)
    print()

    # CFB
    print('-- CFB --')
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    ct = cipher.encrypt(pt)
    dec = AES.new(key, AES.MODE_CFB, iv=iv).decrypt(ct)
    print_hex('IV', iv)
    print_hex('Ciphertext', ct)
    print_hex('Decrypted', dec)
    print()

    # OFB
    print('-- OFB --')
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_OFB, iv=iv)
    ct = cipher.encrypt(pt)
    dec = AES.new(key, AES.MODE_OFB, iv=iv).decrypt(ct)
    print_hex('IV', iv)
    print_hex('Ciphertext', ct)
    print_hex('Decrypted', dec)
    print()

    # CTR
    print('-- CTR --')
    nonce = os.urandom(8)
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    ct = cipher.encrypt(pt)
    dec = AES.new(key, AES.MODE_CTR, nonce=nonce).decrypt(ct)
    print_hex('Nonce', nonce)
    print_hex('Ciphertext', ct)
    print_hex('Decrypted', dec)
    print()

    # GCM
    print('-- GCM --')
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(pt)
    dec_cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    dec = dec_cipher.decrypt_and_verify(ct, tag)
    print_hex('Nonce', nonce)
    print_hex('Ciphertext', ct)
    print_hex('Tag', tag)
    print_hex('Decrypted', dec)
    print()


if __name__ == '__main__':
    run_demo()
