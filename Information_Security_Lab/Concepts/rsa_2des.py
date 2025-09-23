"""Hybrid RSA + Double-DES demo (EDE) for ECB and CBC modes.

This educational demo uses two DES keys (K1,K2) and applies EDE: E_k1(D_k2(E_k1(m))).
It wraps both keys with RSA-OAEP and demonstrates ECB and CBC encryption.
"""
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, DES
from Crypto.Hash import SHA256
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


def ede_encrypt_block(block: bytes, k1: bytes, k2: bytes) -> bytes:
    c1 = DES.new(k1, DES.MODE_ECB).encrypt(block)
    d = DES.new(k2, DES.MODE_ECB).decrypt(c1)
    c2 = DES.new(k1, DES.MODE_ECB).encrypt(d)
    return c2


def ede_decrypt_block(block: bytes, k1: bytes, k2: bytes) -> bytes:
    d1 = DES.new(k1, DES.MODE_ECB).decrypt(block)
    e = DES.new(k2, DES.MODE_ECB).encrypt(d1)
    p = DES.new(k1, DES.MODE_ECB).decrypt(e)
    return p


def generate_rsa(bits: int = 2048):
    key = RSA.generate(bits)
    return key.export_key(), key.publickey().export_key()


def wrap_key(pub_pem: bytes, key_bytes: bytes) -> bytes:
    pub = RSA.import_key(pub_pem)
    cipher = PKCS1_OAEP.new(pub, hashAlgo=SHA256)
    return cipher.encrypt(key_bytes)


def unwrap_key(priv_pem: bytes, wrapped: bytes) -> bytes:
    priv = RSA.import_key(priv_pem)
    cipher = PKCS1_OAEP.new(priv, hashAlgo=SHA256)
    return cipher.decrypt(wrapped)


def double_des_demo(k1: bytes, k2: bytes, plaintext: bytes):
    print('\n=== Double-DES Demo (EDE) ===')
    print_hex('K1', k1)
    print_hex('K2', k2)
    print('Plaintext:', plaintext)

    # ECB
    print('\n-- ECB (EDE) --')
    padded = pkcs7_pad(plaintext)
    ct = b''
    for i in range(0, len(padded), BLOCK):
        ct += ede_encrypt_block(padded[i:i+BLOCK], k1, k2)
    dec = b''
    for i in range(0, len(ct), BLOCK):
        dec += ede_decrypt_block(ct[i:i+BLOCK], k1, k2)
    dec = pkcs7_unpad(dec)
    print_hex('Ciphertext', ct)
    print('Decrypted:', dec)

    # CBC
    print('\n-- CBC (EDE) --')
    iv = get_random_bytes(8)
    padded = pkcs7_pad(plaintext)
    prev = iv
    ct = b''
    for i in range(0, len(padded), BLOCK):
        block = bytes(a ^ b for a, b in zip(padded[i:i+BLOCK], prev))
        encrypted = ede_encrypt_block(block, k1, k2)
        ct += encrypted
        prev = encrypted
    # Decrypt
    prev = iv
    dec = b''
    for i in range(0, len(ct), BLOCK):
        decrypted_block = ede_decrypt_block(ct[i:i+BLOCK], k1, k2)
        dec += bytes(a ^ b for a, b in zip(decrypted_block, prev))
        prev = ct[i:i+BLOCK]
    dec = pkcs7_unpad(dec)
    print_hex('IV', iv)
    print_hex('Ciphertext', ct)
    print('Decrypted:', dec)


def main():
    priv_pem, pub_pem = generate_rsa(2048)
    k1 = get_random_bytes(8)
    k2 = get_random_bytes(8)
    print_hex('\nK1', k1)
    print_hex('K2', k2)
    wrapped1 = wrap_key(pub_pem, k1)
    wrapped2 = wrap_key(pub_pem, k2)
    print_hex('\nWrapped K1', wrapped1)
    print_hex('Wrapped K2', wrapped2)
    un1 = unwrap_key(priv_pem, wrapped1)
    un2 = unwrap_key(priv_pem, wrapped2)
    print_hex('Unwrapped K1', un1)
    print_hex('Unwrapped K2', un2)
    assert un1 == k1 and un2 == k2
    print('Unwrapped keys match')
    plaintext = b'This is a test message for double DES EDE demo.\nLonger than 8 bytes.'
    double_des_demo(k1, k2, plaintext)


if __name__ == '__main__':
    main()
