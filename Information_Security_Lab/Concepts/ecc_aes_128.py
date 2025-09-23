"""Hybrid ECC + AES-128 demo (ECB, CBC, CFB, OFB, CTR).

Uses ECDH (P-256) to derive a KEK via HKDF-SHA256, then AES-GCM to wrap the
symmetric key (authenticated). The wrapped blob is: ephemeral_pub(64) || nonce(12) || ct(tag appended)
"""
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import binascii


def print_hex(label: str, data: bytes):
    print(f"{label}: {binascii.hexlify(data).decode().upper()}")


BLOCK = 16


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
    # ephemeral key
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


def aes_demo(key_bytes: bytes, plaintext: bytes):
    print('\n=== AES-128 Demo ===')
    print_hex('AES-128 key', key_bytes)
    print('Plaintext:', plaintext)

    cipher = AES.new(key_bytes, AES.MODE_ECB)
    padded = pkcs7_pad(plaintext)
    ct = cipher.encrypt(padded)
    dec = AES.new(key_bytes, AES.MODE_ECB).decrypt(ct)
    dec = pkcs7_unpad(dec)
    print('\n-- ECB --')
    print_hex('Ciphertext', ct)
    print('Decrypted:', dec)

    iv = get_random_bytes(16)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv)
    ct = cipher.encrypt(padded)
    dec = AES.new(key_bytes, AES.MODE_CBC, iv=iv).decrypt(ct)
    dec = pkcs7_unpad(dec)
    print('\n-- CBC --')
    print_hex('IV', iv)
    print_hex('Ciphertext', ct)
    print('Decrypted:', dec)

    iv = get_random_bytes(16)
    cipher = AES.new(key_bytes, AES.MODE_CFB, iv=iv)
    ct = cipher.encrypt(plaintext)
    dec = AES.new(key_bytes, AES.MODE_CFB, iv=iv).decrypt(ct)
    print('\n-- CFB --')
    print_hex('IV', iv)
    print_hex('Ciphertext', ct)
    print('Decrypted:', dec)

    iv = get_random_bytes(16)
    cipher = AES.new(key_bytes, AES.MODE_OFB, iv=iv)
    ct = cipher.encrypt(plaintext)
    dec = AES.new(key_bytes, AES.MODE_OFB, iv=iv).decrypt(ct)
    print('\n-- OFB --')
    print_hex('IV', iv)
    print_hex('Ciphertext', ct)
    print('Decrypted:', dec)

    nonce = get_random_bytes(8)
    cipher = AES.new(key_bytes, AES.MODE_CTR, nonce=nonce)
    ct = cipher.encrypt(plaintext)
    dec = AES.new(key_bytes, AES.MODE_CTR, nonce=nonce).decrypt(ct)
    print('\n-- CTR --')
    print_hex('Nonce', nonce)
    print_hex('Ciphertext', ct)
    print('Decrypted:', dec)


def main():
    priv, pub = generate_ec_keypair()
    print('Generated EC keypair (P-256)')

    key_bytes = get_random_bytes(16)
    print_hex('\nGenerated AES-128 key', key_bytes)

    wrapped = wrap_key(pub, key_bytes)
    print_hex('\nWrapped AES key (ECC)', wrapped)

    unwrapped = unwrap_key(priv, wrapped, expected_len=16)
    print_hex('Unwrapped AES key', unwrapped)
    assert unwrapped == key_bytes
    print('Unwrapped key matches')

    plaintext = b'This plaintext is longer than one block to exercise modes.'
    aes_demo(key_bytes, plaintext)


if __name__ == '__main__':
    main()
