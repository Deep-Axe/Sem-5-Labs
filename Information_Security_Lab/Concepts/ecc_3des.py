"""Hybrid ECC + 3DES demo.

Wraps a 24-byte 3DES key using ECDH+HKDF+AES-GCM and demonstrates DES3 modes.
"""
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter
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


def des3_demo(key_bytes: bytes, plaintext: bytes):
    print('\n=== 3DES Demo ===')
    print_hex('3DES key', key_bytes)
    print('Plaintext:', plaintext)

    padded = pkcs7_pad(plaintext)
    cipher = DES3.new(key_bytes, DES3.MODE_ECB)
    ct = cipher.encrypt(padded)
    dec = DES3.new(key_bytes, DES3.MODE_ECB).decrypt(ct)
    dec = pkcs7_unpad(dec)
    print('\n-- ECB --')
    print_hex('Ciphertext', ct)
    print('Decrypted:', dec)

    iv = get_random_bytes(8)
    cipher = DES3.new(key_bytes, DES3.MODE_CBC, iv=iv)
    ct = cipher.encrypt(padded)
    dec = DES3.new(key_bytes, DES3.MODE_CBC, iv=iv).decrypt(ct)
    dec = pkcs7_unpad(dec)
    print('\n-- CBC --')
    print_hex('IV', iv)
    print_hex('Ciphertext', ct)
    print('Decrypted:', dec)

    iv = get_random_bytes(8)
    cipher = DES3.new(key_bytes, DES3.MODE_CFB, iv=iv)
    ct = cipher.encrypt(plaintext)
    dec = DES3.new(key_bytes, DES3.MODE_CFB, iv=iv).decrypt(ct)
    print('\n-- CFB --')
    print_hex('IV', iv)
    print_hex('Ciphertext', ct)
    print('Decrypted:', dec)

    iv = get_random_bytes(8)
    cipher = DES3.new(key_bytes, DES3.MODE_OFB, iv=iv)
    ct = cipher.encrypt(plaintext)
    dec = DES3.new(key_bytes, DES3.MODE_OFB, iv=iv).decrypt(ct)
    print('\n-- OFB --')
    print_hex('IV', iv)
    print_hex('Ciphertext', ct)
    print('Decrypted:', dec)

    ctr = Counter.new(64)
    cipher = DES3.new(key_bytes, DES3.MODE_CTR, counter=ctr)
    ct = cipher.encrypt(plaintext)
    ctr = Counter.new(64)
    dec = DES3.new(key_bytes, DES3.MODE_CTR, counter=ctr).decrypt(ct)
    print('\n-- CTR --')
    print_hex('Ciphertext', ct)
    print('Decrypted:', dec)


def main():
    priv, pub = generate_ec_keypair()
    print('Generated EC keypair (P-256)')

    key_bytes = get_random_bytes(24)
    print_hex('\nGenerated 3DES key', key_bytes)

    wrapped = wrap_key(pub, key_bytes)
    print_hex('\nWrapped 3DES key (ECC)', wrapped)

    unwrapped = unwrap_key(priv, wrapped, expected_len=24)
    print_hex('Unwrapped 3DES key', unwrapped)
    assert unwrapped == key_bytes
    print('Unwrapped key matches')

    plaintext = b'Example plaintext for 3DES demonstration.'
    des3_demo(key_bytes, plaintext)


if __name__ == '__main__':
    main()
