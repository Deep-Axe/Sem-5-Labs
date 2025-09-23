"""Hybrid ElGamal + AES-128 demo (ECB, CBC, CFB, OFB, CTR).

Uses PyCryptodome's ElGamal for wrapping the AES key. This is educational —
ElGamal is not commonly used for key wrapping in this exact way, but it
demonstrates public-key wrapping analogously to RSA-OAEP.
"""
from Crypto.PublicKey import ElGamal
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Random import random as crypto_random
from Crypto import Random
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


def generate_elgamal(bits: int = 2048):
    rng = Random.new().read
    key = ElGamal.generate(bits, rng)
    return key


def elgamal_wrap(pub_key, key_bytes: bytes) -> bytes:
    m = int.from_bytes(key_bytes, 'big')
    # choose random k in [1, p-2]
    k = crypto_random.StrongRandom().randint(1, pub_key.p - 2)
    c1, c2 = pub_key.encrypt(m, k)
    size = (pub_key.p.bit_length() + 7) // 8
    c1b = c1.to_bytes(size, 'big')
    c2b = c2.to_bytes(size, 'big')
    return c1b + c2b


def elgamal_unwrap(priv_key, wrapped: bytes, expected_len: int) -> bytes:
    size = (priv_key.p.bit_length() + 7) // 8
    c1 = int.from_bytes(wrapped[:size], 'big')
    c2 = int.from_bytes(wrapped[size:2*size], 'big')
    m = priv_key.decrypt((c1, c2))
    keyb = m.to_bytes(expected_len, 'big')
    return keyb


def aes_demo(key_bytes: bytes, plaintext: bytes):
    print('\n=== AES-128 Demo ===')
    print_hex('AES-128 key', key_bytes)
    print('Plaintext:', plaintext)

    # ECB
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    padded = pkcs7_pad(plaintext)
    ct = cipher.encrypt(padded)
    dec = AES.new(key_bytes, AES.MODE_ECB).decrypt(ct)
    dec = pkcs7_unpad(dec)
    print('\n-- ECB --')
    print_hex('Ciphertext', ct)
    print('Decrypted:', dec)

    # CBC
    iv = get_random_bytes(16)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv)
    ct = cipher.encrypt(padded)
    dec = AES.new(key_bytes, AES.MODE_CBC, iv=iv).decrypt(ct)
    dec = pkcs7_unpad(dec)
    print('\n-- CBC --')
    print_hex('IV', iv)
    print_hex('Ciphertext', ct)
    print('Decrypted:', dec)

    # CFB
    iv = get_random_bytes(16)
    cipher = AES.new(key_bytes, AES.MODE_CFB, iv=iv)
    ct = cipher.encrypt(plaintext)
    dec = AES.new(key_bytes, AES.MODE_CFB, iv=iv).decrypt(ct)
    print('\n-- CFB --')
    print_hex('IV', iv)
    print_hex('Ciphertext', ct)
    print('Decrypted:', dec)

    # OFB
    iv = get_random_bytes(16)
    cipher = AES.new(key_bytes, AES.MODE_OFB, iv=iv)
    ct = cipher.encrypt(plaintext)
    dec = AES.new(key_bytes, AES.MODE_OFB, iv=iv).decrypt(ct)
    print('\n-- OFB --')
    print_hex('IV', iv)
    print_hex('Ciphertext', ct)
    print('Decrypted:', dec)

    # CTR
    nonce = get_random_bytes(8)
    cipher = AES.new(key_bytes, AES.MODE_CTR, nonce=nonce)
    ct = cipher.encrypt(plaintext)
    dec = AES.new(key_bytes, AES.MODE_CTR, nonce=nonce).decrypt(ct)
    print('\n-- CTR --')
    print_hex('Nonce', nonce)
    print_hex('Ciphertext', ct)
    print('Decrypted:', dec)


def main():
    # Generate ElGamal keypair
    priv = generate_elgamal(2048)
    pub = priv.publickey()
    try:
        p_bits = getattr(priv, 'p').bit_length()
    except Exception:
        p_bits = 'unknown'
    print('Generated ElGamal keypair (p size):', p_bits, 'bits')

    # AES-128 key
    key_bytes = get_random_bytes(16)
    print_hex('\nGenerated AES-128 key', key_bytes)

    wrapped = elgamal_wrap(pub, key_bytes)
    print_hex('\nWrapped AES key (ElGamal)', wrapped)

    unwrapped = elgamal_unwrap(priv, wrapped, expected_len=16)
    print_hex('Unwrapped AES key', unwrapped)
    assert unwrapped == key_bytes
    print('Unwrapped key matches')

    plaintext = b'This plaintext is longer than one block to exercise modes.'
    aes_demo(key_bytes, plaintext)


if __name__ == '__main__':
    main()
