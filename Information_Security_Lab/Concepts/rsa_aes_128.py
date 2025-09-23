"""Hybrid RSA + AES-128 demo (ECB, CBC, CFB, OFB, CTR)."""
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import binascii


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
    return cipher.encrypt(aes_key)


def unwrap_aes_key(priv_pem: bytes, wrapped: bytes) -> bytes:
    priv = RSA.import_key(priv_pem)
    cipher = PKCS1_OAEP.new(priv, hashAlgo=SHA256)
    return cipher.decrypt(wrapped)


def aes_demo(aes_key: bytes, plaintext: bytes):
    print('\n=== AES-128 Demo ===')
    print_hex('AES-128 key', aes_key)
    print('Plaintext:', plaintext)

    # ECB
    print('\n-- ECB --')
    cipher = AES.new(aes_key, AES.MODE_ECB)
    padded = pkcs7_pad(plaintext)
    ct = cipher.encrypt(padded)
    dec = AES.new(aes_key, AES.MODE_ECB).decrypt(ct)
    dec = pkcs7_unpad(dec)
    print_hex('Ciphertext', ct)
    print('Decrypted:', dec)

    # CBC
    print('\n-- CBC --')
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    ct = cipher.encrypt(padded)
    dec = AES.new(aes_key, AES.MODE_CBC, iv=iv).decrypt(ct)
    dec = pkcs7_unpad(dec)
    print_hex('IV', iv)
    print_hex('Ciphertext', ct)
    print('Decrypted:', dec)

    # CFB
    print('\n-- CFB --')
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CFB, iv=iv)
    ct = cipher.encrypt(plaintext)
    dec = AES.new(aes_key, AES.MODE_CFB, iv=iv).decrypt(ct)
    print_hex('IV', iv)
    print_hex('Ciphertext', ct)
    print('Decrypted:', dec)

    # OFB
    print('\n-- OFB --')
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_OFB, iv=iv)
    ct = cipher.encrypt(plaintext)
    dec = AES.new(aes_key, AES.MODE_OFB, iv=iv).decrypt(ct)
    print_hex('IV', iv)
    print_hex('Ciphertext', ct)
    print('Decrypted:', dec)

    # CTR
    print('\n-- CTR --')
    nonce = get_random_bytes(8)
    cipher = AES.new(aes_key, AES.MODE_CTR, nonce=nonce)
    ct = cipher.encrypt(plaintext)
    dec = AES.new(aes_key, AES.MODE_CTR, nonce=nonce).decrypt(ct)
    print_hex('Nonce', nonce)
    print_hex('Ciphertext', ct)
    print('Decrypted:', dec)


def main():
    priv_pem, pub_pem = generate_rsa(2048)
    aes_key = get_random_bytes(16)
    print_hex('\nGenerated AES-128 key', aes_key)
    wrapped = wrap_aes_key(pub_pem, aes_key)
    print_hex('\nWrapped AES key', wrapped)
    unwrapped = unwrap_aes_key(priv_pem, wrapped)
    print_hex('Unwrapped AES key', unwrapped)
    assert unwrapped == aes_key
    print('Unwrapped matches')
    plaintext = b'This is a longer plaintext to exercise AES-128 modes.\nIt spans multiple blocks.'
    aes_demo(aes_key, plaintext)


if __name__ == '__main__':
    main()
