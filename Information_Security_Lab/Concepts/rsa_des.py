"""Hybrid RSA + single DES demo (ECB, CBC, CFB, OFB, CTR)."""
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, DES
from Crypto.Hash import SHA256
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
    if not b:
        return b
    pad_len = b[-1]
    return b[:-pad_len]


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


def des_demo(key_bytes: bytes, plaintext: bytes):
    print('\n=== DES Demo ===')
    print_hex('DES key', key_bytes)
    print('Plaintext:', plaintext)

    # ECB
    print('\n-- ECB --')
    cipher = DES.new(key_bytes, DES.MODE_ECB)
    padded = pkcs7_pad(plaintext)
    ct = cipher.encrypt(padded)
    dec = DES.new(key_bytes, DES.MODE_ECB).decrypt(ct)
    dec = pkcs7_unpad(dec)
    print_hex('Ciphertext', ct)
    print('Decrypted:', dec)

    # CBC
    print('\n-- CBC --')
    iv = get_random_bytes(8)
    cipher = DES.new(key_bytes, DES.MODE_CBC, iv=iv)
    ct = cipher.encrypt(padded)
    dec = DES.new(key_bytes, DES.MODE_CBC, iv=iv).decrypt(ct)
    dec = pkcs7_unpad(dec)
    print_hex('IV', iv)
    print_hex('Ciphertext', ct)
    print('Decrypted:', dec)

    # CFB
    print('\n-- CFB --')
    iv = get_random_bytes(8)
    cipher = DES.new(key_bytes, DES.MODE_CFB, iv=iv)
    ct = cipher.encrypt(plaintext)
    dec = DES.new(key_bytes, DES.MODE_CFB, iv=iv).decrypt(ct)
    print_hex('IV', iv)
    print_hex('Ciphertext', ct)
    print('Decrypted:', dec)

    # OFB
    print('\n-- OFB --')
    iv = get_random_bytes(8)
    cipher = DES.new(key_bytes, DES.MODE_OFB, iv=iv)
    ct = cipher.encrypt(plaintext)
    dec = DES.new(key_bytes, DES.MODE_OFB, iv=iv).decrypt(ct)
    print_hex('IV', iv)
    print_hex('Ciphertext', ct)
    print('Decrypted:', dec)

    # CTR
    print('\n-- CTR --')
    nonce = get_random_bytes(8)
    ctr = Counter.new(64, initial_value=int.from_bytes(nonce, 'big'))
    cipher = DES.new(key_bytes, DES.MODE_CTR, counter=ctr)
    ct = cipher.encrypt(plaintext)
    ctr2 = Counter.new(64, initial_value=int.from_bytes(nonce, 'big'))
    dec = DES.new(key_bytes, DES.MODE_CTR, counter=ctr2).decrypt(ct)
    print_hex('Nonce', nonce)
    print_hex('Ciphertext', ct)
    print('Decrypted:', dec)


def main():
    priv_pem, pub_pem = generate_rsa(2048)
    key_bytes = get_random_bytes(8)
    print_hex('\nGenerated DES key', key_bytes)
    wrapped = wrap_key(pub_pem, key_bytes)
    print_hex('\nWrapped DES key', wrapped)
    unwrapped = unwrap_key(priv_pem, wrapped)
    print_hex('Unwrapped DES key', unwrapped)
    assert unwrapped == key_bytes
    print('Unwrapped matches')
    plaintext = b'This is a test plaintext for single DES demo.\nLonger than 8 bytes.'
    des_demo(key_bytes, plaintext)


if __name__ == '__main__':
    main()
