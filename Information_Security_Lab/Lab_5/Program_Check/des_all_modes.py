"""Demonstrate single-DES (8-byte key) across common modes: ECB, CBC, CFB, OFB, CTR.

Uses PKCS#7 padding for ECB/CBC (8-byte block size). Prints hex outputs.
"""
from Crypto.Cipher import DES
from Crypto.Util import Counter
import os

BLOCK = 8


def print_hex(label, data: bytes):
    print(f"{label}: {data.hex()}")


def pkcs7_pad(b: bytes) -> bytes:
    pad_len = BLOCK - (len(b) % BLOCK)
    return b + bytes([pad_len]) * pad_len


def pkcs7_unpad(b: bytes) -> bytes:
    if not b:
        return b
    pad_len = b[-1]
    if pad_len < 1 or pad_len > BLOCK:
        raise ValueError('Invalid padding')
    if b[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError('Invalid padding bytes')
    return b[:-pad_len]


def run_demo():
    print('=== Single DES All Modes Demo ===')
    key = b'K' * 8  # 8 bytes -> DES key
    pt = b'HelloDES!'  # arbitrary length
    print_hex('Key', key)
    print_hex('Plaintext', pt)
    print()

    # ECB
    print('-- ECB --')
    cipher = DES.new(key, DES.MODE_ECB)
    padded = pkcs7_pad(pt)
    ct = cipher.encrypt(padded)
    dec = DES.new(key, DES.MODE_ECB).decrypt(ct)
    dec = pkcs7_unpad(dec)
    print_hex('Ciphertext', ct)
    print_hex('Decrypted', dec)
    print()

    # CBC
    print('-- CBC --')
    iv = os.urandom(8)
    cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    padded = pkcs7_pad(pt)
    ct = cipher.encrypt(padded)
    dec = DES.new(key, DES.MODE_CBC, iv=iv).decrypt(ct)
    dec = pkcs7_unpad(dec)
    print_hex('IV', iv)
    print_hex('Ciphertext', ct)
    print_hex('Decrypted', dec)
    print()

    # CFB
    print('-- CFB --')
    iv = os.urandom(8)
    cipher = DES.new(key, DES.MODE_CFB, iv=iv)
    ct = cipher.encrypt(pt)
    dec = DES.new(key, DES.MODE_CFB, iv=iv).decrypt(ct)
    print_hex('IV', iv)
    print_hex('Ciphertext', ct)
    print_hex('Decrypted', dec)
    print()

    # OFB
    print('-- OFB --')
    iv = os.urandom(8)
    cipher = DES.new(key, DES.MODE_OFB, iv=iv)
    ct = cipher.encrypt(pt)
    dec = DES.new(key, DES.MODE_OFB, iv=iv).decrypt(ct)
    print_hex('IV', iv)
    print_hex('Ciphertext', ct)
    print_hex('Decrypted', dec)
    print()

    # CTR
    print('-- CTR --')
    # Using 64-bit counter (8 bytes) for DES block size
    nonce = os.urandom(8)
    ctr = Counter.new(64, initial_value=int.from_bytes(nonce, 'big'))
    cipher = DES.new(key, DES.MODE_CTR, counter=ctr)
    ct = cipher.encrypt(pt)
    # Recreate counter for decryption
    ctr2 = Counter.new(64, initial_value=int.from_bytes(nonce, 'big'))
    dec = DES.new(key, DES.MODE_CTR, counter=ctr2).decrypt(ct)
    print_hex('Nonce', nonce)
    print_hex('Ciphertext', ct)
    print_hex('Decrypted', dec)
    print()


if __name__ == '__main__':
    run_demo()
