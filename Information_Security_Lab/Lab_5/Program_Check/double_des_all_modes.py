"""Demonstrate Double-DES (2DES) in common modes using two 8-byte keys.

This uses EDE (encrypt-decrypt-encrypt) pattern with two keys.
Not secure for production; shown for educational purposes.
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
    pad_len = b[-1]
    return b[:-pad_len]


def ede_encrypt(block: bytes, k1: bytes, k2: bytes) -> bytes:
    # E_k1(D_k2(E_k1(block))) - but typical 2DES EDE uses K1,K2 (we implement EDE)
    c1 = DES.new(k1, DES.MODE_ECB).encrypt(block)
    d = DES.new(k2, DES.MODE_ECB).decrypt(c1)
    c2 = DES.new(k1, DES.MODE_ECB).encrypt(d)
    return c2


def ede_decrypt(block: bytes, k1: bytes, k2: bytes) -> bytes:
    d1 = DES.new(k1, DES.MODE_ECB).decrypt(block)
    e = DES.new(k2, DES.MODE_ECB).encrypt(d1)
    p = DES.new(k1, DES.MODE_ECB).decrypt(e)
    return p


def run_demo():
    print('=== Double DES (2DES) All Modes Demo ===')
    k1 = b'K1K1K1K1'
    k2 = b'K2K2K2K2'
    pt = b'HelloDoubleDES'  # arbitrary length
    print_hex('K1', k1)
    print_hex('K2', k2)
    print_hex('Plaintext', pt)
    print()

    # ECB (pad)
    print('-- ECB --')
    padded = pkcs7_pad(pt)
    ct_blocks = b''
    for i in range(0, len(padded), BLOCK):
        ct_blocks += ede_encrypt(padded[i:i+BLOCK], k1, k2)
    # Decrypt
    dec = b''
    for i in range(0, len(ct_blocks), BLOCK):
        dec += ede_decrypt(ct_blocks[i:i+BLOCK], k1, k2)
    dec = pkcs7_unpad(dec)
    print_hex('Ciphertext', ct_blocks)
    print_hex('Decrypted', dec)
    print()

    # CBC (simple implementation chaining ECB EDE manually)
    print('-- CBC --')
    iv = os.urandom(8)
    padded = pkcs7_pad(pt)
    prev = iv
    ct = b''
    for i in range(0, len(padded), BLOCK):
        block = bytes(a ^ b for a, b in zip(padded[i:i+BLOCK], prev))
        enc = ede_encrypt(block, k1, k2)
        ct += enc
        prev = enc
    # Decrypt
    prev = iv
    dec = b''
    for i in range(0, len(ct), BLOCK):
        decrypted_block = ede_decrypt(ct[i:i+BLOCK], k1, k2)
        dec += bytes(a ^ b for a, b in zip(decrypted_block, prev))
        prev = ct[i:i+BLOCK]
    dec = pkcs7_unpad(dec)
    print_hex('IV', iv)
    print_hex('Ciphertext', ct)
    print_hex('Decrypted', dec)
    print()

    # For streaming modes (CFB, OFB, CTR) using library DES and applying EDE is complex
    # and beyond the basic demo. We'll show CTR by building a single DES CTR stream
    # with the first key and then apply second and first as needed per-block which
    # would be implemented similarly. For brevity, we skip other modes here.


if __name__ == '__main__':
    run_demo()
