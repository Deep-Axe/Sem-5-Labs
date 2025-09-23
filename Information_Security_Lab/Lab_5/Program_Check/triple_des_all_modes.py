"""Demonstrate Triple-DES (3DES) across common modes: ECB, CBC, CFB, OFB, CTR.

Uses Crypto.Cipher.DES3 where available. Includes PKCS#7 padding for ECB/CBC.
"""
from Crypto.Cipher import DES3
from Crypto.Util import Counter
import os

BLOCK = 8


def print_hex(label, data: bytes):
    print(f"{label}: {data.hex()}")


def pkcs7_pad(b: bytes) -> bytes:
    pad_len = BLOCK - (len(b) % BLOCK)
    return b + bytes([pad_len]) * pad_len


def pkcs7_unpad(b: bytes) -> bytes:
    pad_len = b[-1]
    return b[:-pad_len]


def run_demo():
    print('=== Triple DES (3DES) All Modes Demo ===')
    # 24-byte key for 3DES (EDE3)
    key = DES3.adjust_key_parity(b'012345670123456701234567')
    pt = b'HelloTripleDES'  # arbitrary length
    print_hex('Key', key)
    print_hex('Plaintext', pt)
    print()

    # ECB
    print('-- ECB --')
    padded = pkcs7_pad(pt)
    cipher = DES3.new(key, DES3.MODE_ECB)
    ct = cipher.encrypt(padded)
    dec = DES3.new(key, DES3.MODE_ECB).decrypt(ct)
    dec = pkcs7_unpad(dec)
    print_hex('Ciphertext', ct)
    print_hex('Decrypted', dec)
    print()

    # CBC
    print('-- CBC --')
    iv = os.urandom(8)
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    ct = cipher.encrypt(padded)
    dec = DES3.new(key, DES3.MODE_CBC, iv=iv).decrypt(ct)
    dec = pkcs7_unpad(dec)
    print_hex('IV', iv)
    print_hex('Ciphertext', ct)
    print_hex('Decrypted', dec)
    print()

    # CFB
    print('-- CFB --')
    iv = os.urandom(8)
    cipher = DES3.new(key, DES3.MODE_CFB, iv=iv)
    ct = cipher.encrypt(pt)
    dec = DES3.new(key, DES3.MODE_CFB, iv=iv).decrypt(ct)
    print_hex('IV', iv)
    print_hex('Ciphertext', ct)
    print_hex('Decrypted', dec)
    print()

    # OFB
    print('-- OFB --')
    iv = os.urandom(8)
    cipher = DES3.new(key, DES3.MODE_OFB, iv=iv)
    ct = cipher.encrypt(pt)
    dec = DES3.new(key, DES3.MODE_OFB, iv=iv).decrypt(ct)
    print_hex('IV', iv)
    print_hex('Ciphertext', ct)
    print_hex('Decrypted', dec)
    print()

    # CTR
    print('-- CTR --')
    nonce = os.urandom(8)
    ctr = Counter.new(64, initial_value=int.from_bytes(nonce, 'big'))
    cipher = DES3.new(key, DES3.MODE_CTR, counter=ctr)
    ct = cipher.encrypt(pt)
    ctr2 = Counter.new(64, initial_value=int.from_bytes(nonce, 'big'))
    dec = DES3.new(key, DES3.MODE_CTR, counter=ctr2).decrypt(ct)
    print_hex('Nonce', nonce)
    print_hex('Ciphertext', ct)
    print_hex('Decrypted', dec)
    print()


if __name__ == '__main__':
    run_demo()
