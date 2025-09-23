"""Hybrid Rabin + AES-192 demo (ECB, CBC, CFB, OFB, CTR)."""
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import number
import binascii


def print_hex(label: str, data: bytes):
    print(f"{label}: {binascii.hexlify(data).decode().upper()}")


BLOCK = 16
MARKER = b"\xAA\x55"


def pkcs7_pad(b: bytes) -> bytes:
    pad_len = BLOCK - (len(b) % BLOCK)
    return b + bytes([pad_len]) * pad_len


def pkcs7_unpad(b: bytes) -> bytes:
    pad_len = b[-1]
    return b[:-pad_len]


def egcd(a: int, b: int):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError('No modular inverse')
    return x % m


def generate_rabin(bits: int = 2048):
    half = bits // 2
    while True:
        p = number.getPrime(half)
        if p % 4 == 3:
            break
    while True:
        q = number.getPrime(half)
        if q % 4 == 3 and q != p:
            break
    n = p * q
    return {'p': p, 'q': q, 'n': n}


def rabin_encrypt(pub_n: int, m: int) -> int:
    return pow(m, 2, pub_n)


def rabin_decrypt(priv: dict, c: int):
    p = priv['p']
    q = priv['q']
    n = priv['n']
    r_p = pow(c, (p + 1) // 4, p)
    r_q = pow(c, (q + 1) // 4, q)
    inv_q_mod_p = modinv(q, p)
    inv_p_mod_q = modinv(p, q)
    candidates = []
    for a in (r_p, (-r_p) % p):
        for b in (r_q, (-r_q) % q):
            x = (a * q * inv_q_mod_p + b * p * inv_p_mod_q) % n
            candidates.append(x)
    unique = list(dict.fromkeys(candidates))
    return unique


def wrap_key(pub: dict, key_bytes: bytes) -> bytes:
    n = pub['n']
    m_bytes = key_bytes + MARKER
    m = int.from_bytes(m_bytes, 'big')
    if m >= n:
        raise ValueError('message too large for modulus')
    c = rabin_encrypt(n, m)
    size = (n.bit_length() + 7) // 8
    return c.to_bytes(size, 'big')


def unwrap_key(priv: dict, wrapped: bytes, expected_len: int) -> bytes:
    n = priv['n']
    c = int.from_bytes(wrapped, 'big')
    roots = rabin_decrypt(priv, c)
    for r in roots:
        b = r.to_bytes((r.bit_length() + 7) // 8 or 1, 'big')
        if len(b) < expected_len + len(MARKER):
            b = (b'\x00' * (expected_len + len(MARKER) - len(b))) + b
        if b.endswith(MARKER):
            return b[: -len(MARKER)]
    raise ValueError('no valid root found')


def aes_demo(key_bytes: bytes, plaintext: bytes):
    print('\n=== AES-192 Demo ===')
    print_hex('AES-192 key', key_bytes)
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
    priv = generate_rabin(2048)
    pub = {'n': priv['n']}
    print('Generated Rabin keypair (n bits):', priv['n'].bit_length())

    key_bytes = get_random_bytes(24)
    print_hex('\nGenerated AES-192 key', key_bytes)

    wrapped = wrap_key(pub, key_bytes)
    print_hex('\nWrapped AES key (Rabin)', wrapped)

    unwrapped = unwrap_key(priv, wrapped, expected_len=24)
    print_hex('Unwrapped AES key', unwrapped)
    assert unwrapped == key_bytes
    print('Unwrapped key matches')

    plaintext = b'This plaintext is longer than one block to exercise modes.'
    aes_demo(key_bytes, plaintext)


if __name__ == '__main__':
    main()
