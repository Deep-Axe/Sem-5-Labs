"""Hybrid ECC + 2DES (EDE) demo.

Wraps two DES keys using ECDH + HKDF + AES-GCM and performs EDE demonstrations.
"""
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
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


def generate_ec_keypair():
    priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
    pub = priv.public_key()
    return priv, pub


def pubkey_bytes(pub):
    nums = pub.public_numbers()
    x = nums.x.to_bytes(32, 'big')
    y = nums.y.to_bytes(32, 'big')
    return x + y


def wrap_key(recipient_pub, key_bytes: bytes) -> bytes:
    eph_priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
    eph_pub = eph_priv.public_key()
    eph_bytes = pubkey_bytes(eph_pub)
    shared = eph_priv.exchange(ec.ECDH(), recipient_pub)
    kek = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'ecc-wrap', backend=default_backend()).derive(shared)
    aesgcm = AESGCM(kek)
    nonce = get_random_bytes(12)
    ct = aesgcm.encrypt(nonce, key_bytes, eph_bytes)
    return eph_bytes + nonce + ct


def unwrap_key(recipient_priv, wrapped: bytes, expected_len: int) -> bytes:
    eph_bytes = wrapped[:64]
    nonce = wrapped[64:76]
    ct = wrapped[76:]
    x = int.from_bytes(eph_bytes[:32], 'big')
    y = int.from_bytes(eph_bytes[32:], 'big')
    peer_pub = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key(default_backend())
    shared = recipient_priv.exchange(ec.ECDH(), peer_pub)
    kek = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'ecc-wrap', backend=default_backend()).derive(shared)
    aesgcm = AESGCM(kek)
    key_bytes = aesgcm.decrypt(nonce, ct, eph_bytes)
    return key_bytes


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
    ct_blocks = []
    for i in range(0, len(padded), 8):
        block = padded[i:i+8]
        ct_blocks.append(ede_encrypt_block(block, k1, k2))
    ct = b''.join(ct_blocks)
    dec_blocks = []
    for i in range(0, len(ct), 8):
        dec_blocks.append(ede_decrypt_block(ct[i:i+8], k1, k2))
    dec = b''.join(dec_blocks)
    dec = pkcs7_unpad(dec)
    print('\n-- ECB (EDE) --')
    print_hex('Ciphertext', ct)
    print('Decrypted:', dec)

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
    priv, pub = generate_ec_keypair()
    print('Generated EC keypair (P-256)')

    k1 = get_random_bytes(8)
    k2 = get_random_bytes(8)
    print_hex('\nK1', k1)
    print_hex('K2', k2)

    wrapped1 = wrap_key(pub, k1)
    wrapped2 = wrap_key(pub, k2)
    print_hex('\nWrapped K1', wrapped1)
    print_hex('Wrapped K2', wrapped2)

    unwrapped1 = unwrap_key(priv, wrapped1, expected_len=8)
    unwrapped2 = unwrap_key(priv, wrapped2, expected_len=8)
    print_hex('Unwrapped K1', unwrapped1)
    print_hex('Unwrapped K2', unwrapped2)
    assert unwrapped1 == k1 and unwrapped2 == k2
    print('Unwrapped keys match')

    plaintext = b'This is a sample plaintext for 2DES EDE demo.'
    two_des_demo(k1, k2, plaintext)


if __name__ == '__main__':
    main()
