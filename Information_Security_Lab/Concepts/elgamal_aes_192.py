"""Hybrid ElGamal + AES-192 demo (ECB, CBC, CFB, OFB, CTR)."""
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


def aes_demo(key_bytes: bytes, plaintext: bytes):
    print('\n=== AES-192 Demo ===')
    print_hex('AES-192 key', key_bytes)
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
    priv = generate_elgamal(2048)
    pub = priv.publickey()
    try:
        p_bits = getattr(priv, 'p').bit_length()
    except Exception:
        p_bits = 'unknown'
    print('Generated ElGamal keypair (p size):', p_bits, 'bits')

    key_bytes = get_random_bytes(24)
    print_hex('\nGenerated AES-192 key', key_bytes)

    wrapped = elgamal_wrap(pub, key_bytes)
    print_hex('\nWrapped AES key (ElGamal)', wrapped)

    unwrapped = elgamal_unwrap(priv, wrapped, expected_len=24)
    print_hex('Unwrapped AES key', unwrapped)
    assert unwrapped == key_bytes
    print('Unwrapped key matches')

    plaintext = b'This plaintext is longer than one block to exercise modes.'
    aes_demo(key_bytes, plaintext)


if __name__ == '__main__':
    main()
