"""Hybrid RSA + AES-192 demo with hash checks (MD5, SHA1, SHA256).

This script extends the RSA+AES-192 demo by computing MD5, SHA1 and SHA256
hashes of the plaintext before encryption and verifying those hashes after
decryption for each demonstrated mode.

It otherwise mirrors the original `rsa_aes_192.py` behavior (RSA-OAEP wrapping
of a random AES-192 key and AES encryption in ECB/CBC/CFB/OFB/CTR modes).
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import binascii
import hashlib


def print_hex(label: str, data: bytes):
    print(f"{label}: {binascii.hexlify(data).decode().upper()}")


BLOCK = 16


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


def generate_rsa(bits: int = 2048):
    key = RSA.generate(bits)
    priv_pem = key.export_key()
    pub_pem = key.publickey().export_key()
    print('Generated RSA keypair:')
    print(f'  modulus n ({key.n.bit_length()} bits)')
    print('  public exponent e =', key.e)
    return priv_pem, pub_pem


def wrap_aes_key(pub_pem: bytes, aes_key: bytes) -> bytes:
    pub = RSA.import_key(pub_pem)
    cipher = PKCS1_OAEP.new(pub, hashAlgo=SHA256)
    wrapped = cipher.encrypt(aes_key)
    return wrapped


def unwrap_aes_key(priv_pem: bytes, wrapped: bytes) -> bytes:
    priv = RSA.import_key(priv_pem)
    cipher = PKCS1_OAEP.new(priv, hashAlgo=SHA256)
    key = cipher.decrypt(wrapped)
    return key


def compute_hashes(data: bytes) -> dict:
    """Return a dict with md5, sha1, sha256 hex digests for data."""
    return {
        'md5': hashlib.md5(data).hexdigest(),
        'sha1': hashlib.sha1(data).hexdigest(),
        'sha256': hashlib.sha256(data).hexdigest(),
    }


def verify_hashes(orig: dict, newdata: bytes) -> dict:
    new = compute_hashes(newdata)
    return {k: (orig[k] == new[k]) for k in orig}


def aes_demo_all_modes(aes_key: bytes, plaintext: bytes):
    print('\n=== AES-192 Demo for multiple modes (with hash checks) ===')
    print_hex('AES-192 key', aes_key)
    print('Plaintext:', plaintext)

    orig_hashes = compute_hashes(plaintext)
    print('\nOriginal hashes:')
    print(f"  MD5:    {orig_hashes['md5']}")
    print(f"  SHA1:   {orig_hashes['sha1']}")
    print(f"  SHA256: {orig_hashes['sha256']}")

    # ECB (needs padding)
    print('\n-- ECB (PKCS#7 padding) --')
    cipher = AES.new(aes_key, AES.MODE_ECB)
    padded = pkcs7_pad(plaintext)
    ct = cipher.encrypt(padded)
    dec = AES.new(aes_key, AES.MODE_ECB).decrypt(ct)
    dec = pkcs7_unpad(dec)
    print_hex('Ciphertext', ct)
    print('Decrypted:', dec)
    v = verify_hashes(orig_hashes, dec)
    print('Hash verification:', v)

    # CBC (IV + padding)
    print('\n-- CBC (random IV, PKCS#7 padding) --')
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    padded = pkcs7_pad(plaintext)
    ct = cipher.encrypt(padded)
    dec = AES.new(aes_key, AES.MODE_CBC, iv=iv).decrypt(ct)
    dec = pkcs7_unpad(dec)
    print_hex('IV', iv)
    print_hex('Ciphertext', ct)
    print('Decrypted:', dec)
    v = verify_hashes(orig_hashes, dec)
    print('Hash verification:', v)

    # CFB (no padding required)
    print('\n-- CFB (random IV) --')
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CFB, iv=iv)
    ct = cipher.encrypt(plaintext)
    dec = AES.new(aes_key, AES.MODE_CFB, iv=iv).decrypt(ct)
    print_hex('IV', iv)
    print_hex('Ciphertext', ct)
    print('Decrypted:', dec)
    v = verify_hashes(orig_hashes, dec)
    print('Hash verification:', v)

    # OFB (no padding)
    print('\n-- OFB (random IV) --')
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_OFB, iv=iv)
    ct = cipher.encrypt(plaintext)
    dec = AES.new(aes_key, AES.MODE_OFB, iv=iv).decrypt(ct)
    print_hex('IV', iv)
    print_hex('Ciphertext', ct)
    print('Decrypted:', dec)
    v = verify_hashes(orig_hashes, dec)
    print('Hash verification:', v)

    # CTR (nonce-based)
    print('\n-- CTR (random nonce) --')
    nonce = get_random_bytes(8)  # 64-bit nonce
    cipher = AES.new(aes_key, AES.MODE_CTR, nonce=nonce)
    ct = cipher.encrypt(plaintext)
    dec = AES.new(aes_key, AES.MODE_CTR, nonce=nonce).decrypt(ct)
    print_hex('Nonce', nonce)
    print_hex('Ciphertext', ct)
    print('Decrypted:', dec)
    v = verify_hashes(orig_hashes, dec)
    print('Hash verification:', v)


def main():
    # Generate RSA keypair
    priv_pem, pub_pem = generate_rsa(2048)

    # Generate AES-192 key (24 bytes)
    aes_key = get_random_bytes(24)
    print_hex('\nGenerated AES-192 key', aes_key)

    # Wrap AES key with RSA-OAEP(SHA-256)
    wrapped = wrap_aes_key(pub_pem, aes_key)
    print_hex('\nWrapped AES key (RSA-OAEP)', wrapped)

    # Unwrap with private key and verify
    unwrapped = unwrap_aes_key(priv_pem, wrapped)
    print_hex('Unwrapped AES key', unwrapped)
    assert unwrapped == aes_key, 'Unwrapped key does not match original AES key!'
    print('Unwrapped key matches original')

    # Prepare a plaintext longer than one block to exercise padding
    plaintext = b'This is a test message for AES-192 across multiple modes.\nIt is longer than 16 bytes.'

    # Run AES demos with hash checks
    aes_demo_all_modes(aes_key, plaintext)


if __name__ == '__main__':
    main()
