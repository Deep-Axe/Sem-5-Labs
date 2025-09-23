"""Hybrid Rabin + 2DES (EDE) demo.

Wraps two DES keys using Rabin and demonstrates EDE in ECB and CBC.
"""
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util import number
import binascii


def print_hex(label: str, data: bytes):
    print(f"{label}: {binascii.hexlify(data).decode().upper()}")


BLOCK = 8
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
    r_p = pow(c, (p + 1) // 4, p)
    r_q = pow(c, (q + 1) // 4, q)
    inv_q_mod_p = modinv(q, p)
    inv_p_mod_q = modinv(p, q)
    candidates = []
    for a in (r_p, (-r_p) % p):
        for b in (r_q, (-r_q) % q):
            x = (a * q * inv_q_mod_p + b * p * inv_p_mod_q) % (p * q)
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
    priv = generate_rabin(2048)
    pub = {'n': priv['n']}
    print('Generated Rabin keypair (n bits):', priv['n'].bit_length())

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
