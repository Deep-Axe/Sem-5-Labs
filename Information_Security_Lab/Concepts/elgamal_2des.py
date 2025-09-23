"""Hybrid ElGamal + 2DES (EDE) demo.

This script demonstrates wrapping two DES keys with ElGamal and performing
EDE (encrypt-decrypt-encrypt) with DES in ECB and CBC modes.
"""
from Crypto.PublicKey import ElGamal
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Random import random as crypto_random
from Crypto import Random
import binascii


def print_hex(label: str, data: bytes):
    print(f"{label}: {binascii.hexlify(data).decode().upper()}")


BLOCK = 8


def pkcs7_pad(b: bytes) -> bytes:
    pad_len = BLOCK - (len(b) % BLOCK)
    return b + bytes([pad_len]) * pad_len


def pkcs7_unpad(b: bytes) -> bytes:
    pad_len = b[-1]
    return b[:-pad_len]


def generate_elgamal(bits: int = 2048):
    rng = Random.new().read
    return ElGamal.generate(bits, rng)


def elgamal_wrap(pub_key, key_bytes: bytes) -> bytes:
    m = int.from_bytes(key_bytes, 'big')
    try:
        p_val = getattr(pub_key, 'p')
        k = crypto_random.StrongRandom().randint(1, p_val - 2)
        size = (p_val.bit_length() + 7) // 8
    except Exception:
        k = crypto_random.StrongRandom().randint(1, 1 << 2046)
        size = 256
    c1, c2 = pub_key.encrypt(m, k)
    return c1.to_bytes(size, 'big') + c2.to_bytes(size, 'big')


def elgamal_unwrap(priv_key, wrapped: bytes, expected_len: int) -> bytes:
    try:
        p_val = getattr(priv_key, 'p')
        size = (p_val.bit_length() + 7) // 8
    except Exception:
        size = 256
    c1 = int.from_bytes(wrapped[:size], 'big')
    c2 = int.from_bytes(wrapped[size:2*size], 'big')
    m = priv_key.decrypt((c1, c2))
    return m.to_bytes(expected_len, 'big')


def ede_encrypt_block(block: bytes, k1: bytes, k2: bytes) -> bytes:
    d1 = DES.new(k1, DES.MODE_ECB)
    d2 = DES.new(k2, DES.MODE_ECB)
    return d1.encrypt(d2.decrypt(d1.encrypt(block)))


def ede_decrypt_block(block: bytes, k1: bytes, k2: bytes) -> bytes:
    d1 = DES.new(k1, DES.MODE_ECB)
    d2 = DES.new(k2, DES.MODE_ECB)
    return d1.decrypt(d2.encrypt(d1.decrypt(block)))


def two_des_demo(k1: bytes, k2: bytes, plaintext: bytes):
    print('\n=== 2DES (EDE) Demo ===')
    print_hex('K1', k1)
    print_hex('K2', k2)
    print('Plaintext:', plaintext)

    padded = pkcs7_pad(plaintext)

    # ECB - operate on 8-byte blocks
    ct_blocks = []
    for i in range(0, len(padded), 8):
        block = padded[i:i+8]
        ct_blocks.append(ede_encrypt_block(block, k1, k2))
    ct = b''.join(ct_blocks)

    # Decrypt
    dec_blocks = []
    for i in range(0, len(ct), 8):
        dec_blocks.append(ede_decrypt_block(ct[i:i+8], k1, k2))
    dec = b''.join(dec_blocks)
    dec = pkcs7_unpad(dec)
    print('\n-- ECB (EDE) --')
    print_hex('Ciphertext', ct)
    print('Decrypted:', dec)

    # CBC - naive implementation using ECB block ops and XOR chaining
    iv = get_random_bytes(8)
    blocks = [padded[i:i+8] for i in range(0, len(padded), 8)]
    ct_blocks = []
    prev = iv
    for block in blocks:
        xored = bytes(a ^ b for a, b in zip(block, prev))
        ct_blk = ede_encrypt_block(xored, k1, k2)
        ct_blocks.append(ct_blk)
        prev = ct_blk
    ct = b''.join(ct_blocks)

    # CBC Decrypt
    prev = iv
    dec_blocks = []
    for ct_blk in ct_blocks:
        decrypted = ede_decrypt_block(ct_blk, k1, k2)
        dec_blocks.append(bytes(a ^ b for a, b in zip(decrypted, prev)))
        prev = ct_blk
    dec = b''.join(dec_blocks)
    dec = pkcs7_unpad(dec)
    print('\n-- CBC (EDE) --')
    print_hex('IV', iv)
    print_hex('Ciphertext', ct)
    print('Decrypted:', dec)


def main():
    priv = generate_elgamal(2048)
    pub = priv.publickey()
    try:
        p_bits = getattr(priv, 'p').bit_length()
    except Exception:
        p_bits = 'unknown'
    print('Generated ElGamal keypair (p size):', p_bits)

    k1 = get_random_bytes(8)
    k2 = get_random_bytes(8)
    print_hex('\nK1', k1)
    print_hex('K2', k2)

    wrapped1 = elgamal_wrap(pub, k1)
    wrapped2 = elgamal_wrap(pub, k2)
    print_hex('\nWrapped K1', wrapped1)
    print_hex('Wrapped K2', wrapped2)

    unwrapped1 = elgamal_unwrap(priv, wrapped1, expected_len=8)
    unwrapped2 = elgamal_unwrap(priv, wrapped2, expected_len=8)
    print_hex('Unwrapped K1', unwrapped1)
    print_hex('Unwrapped K2', unwrapped2)
    assert unwrapped1 == k1 and unwrapped2 == k2
    print('Unwrapped keys match')

    plaintext = b'This is a sample plaintext for 2DES EDE demo.'
    two_des_demo(k1, k2, plaintext)


if __name__ == '__main__':
    main()
