"""PKSE lab demo using the Paillier cryptosystem.

Implements:
- Dataset: 10+ documents
- Paillier key generation, encrypt/decrypt of integers
- Encrypted inverted index: word -> list of encrypted doc IDs
- Search: lookup encrypted postings for query word and decrypt using private key

This is an educational implementation (toy Paillier). For production use,
use audited libraries and consider security parameters carefully.
"""
from Crypto.Util import number
import math
import random
import json
import string
import binascii


def generate_dataset():
    docs = [
        "The quick brown fox jumps over the lazy dog",
        "Alice and Bob study cryptography and network security",
        "Paillier enables additive homomorphism on integers",
        "Private information retrieval and searchable encryption are related topics",
        "Python is a popular programming language for security research",
        "Data structures include lists dictionaries sets and tuples",
        "The lab exercises cover AES RSA ECC and hashing algorithms",
        "Design patterns help build maintainable and testable software",
        "Fast hashing functions are used for checksums and bloom filters",
        "Threshold and multi-party variants extend public-key schemes"
    ]
    return docs


def normalize(text: str) -> list:
    trans = str.maketrans('', '', string.punctuation)
    cleaned = text.translate(trans).lower()
    return [w for w in cleaned.split() if w]


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


def lcm(a: int, b: int) -> int:
    return a // math.gcd(a, b) * b


class PaillierPrivateKey:
    def __init__(self, p: int, q: int, n: int, lam: int, mu: int):
        self.p = p
        self.q = q
        self.n = n
        self.lam = lam
        self.mu = mu


class PaillierPublicKey:
    def __init__(self, n: int, g: int):
        self.n = n
        self.g = g


def generate_paillier(bits: int = 1024):
    # generate p, q primes where p != q
    half = bits // 2
    p = number.getPrime(half)
    q = number.getPrime(half)
    while q == p:
        q = number.getPrime(half)
    n = p * q
    nsq = n * n

    # choose g = n + 1 (common simplification)
    g = n + 1

    lam = lcm(p - 1, q - 1)

    # compute mu = (L(g^lambda mod n^2))^{-1} mod n
    def L(u):
        return (u - 1) // n

    x = pow(g, lam, nsq)
    l_of_x = L(x)
    mu = modinv(l_of_x, n)

    pub = PaillierPublicKey(n, g)
    priv = PaillierPrivateKey(p, q, n, lam, mu)
    return pub, priv


def paillier_encrypt(pub: PaillierPublicKey, m: int) -> int:
    n = pub.n
    nsq = n * n
    if not (0 <= m < n):
        raise ValueError('plaintext out of range')
    while True:
        r = random.randrange(1, n)
        if math.gcd(r, n) == 1:
            break
    # c = g^m * r^n mod n^2
    c = (pow(pub.g, m, nsq) * pow(r, n, nsq)) % nsq
    return c


def paillier_decrypt(priv: PaillierPrivateKey, c: int) -> int:
    n = priv.n
    nsq = n * n
    def L(u):
        return (u - 1) // n
    x = pow(c, priv.lam, nsq)
    l_of_x = L(x)
    m = (l_of_x * priv.mu) % n
    return m


def build_encrypted_index(docs: list, pub: PaillierPublicKey):
    raw_index = {}
    for doc_id, text in enumerate(docs):
        for w in normalize(text):
            raw_index.setdefault(w, set()).add(doc_id)

    enc_index = {}
    for w, s in raw_index.items():
        postings = sorted(list(s))
        # encrypt each doc id as integer
        ciphers = [hex(paillier_encrypt(pub, d)) for d in postings]
        enc_index[w] = ciphers
    return enc_index


def decrypt_postings(enc_list: list, priv: PaillierPrivateKey) -> list:
    res = []
    for c_hex in enc_list:
        c = int(c_hex, 16)
        m = paillier_decrypt(priv, c)
        res.append(m)
    return res


def demo():
    docs = generate_dataset()
    print('Documents:')
    for i, d in enumerate(docs):
        print(f'{i}: {d}')

    print('\nGenerating Paillier keypair (1024-bit modulus)...')
    pub, priv = generate_paillier(1024)
    print('Public modulus n (bits):', pub.n.bit_length())

    print('\nBuilding encrypted index...')
    enc_index = build_encrypted_index(docs, pub)
    sample_keys = list(enc_index.keys())[:8]
    print('Sample encrypted postings (word -> [ciphertexts hex]):')
    for k in sample_keys:
        print(f'{k} -> {enc_index[k]}')

    # demo search flow
    queries = ['encryption', 'python', 'data', 'paillier', 'hashing']
    print('\nSearch demo:')
    for q in queries:
        print(f"\nQuery: {q}")
        enc_postings = enc_index.get(q)
        if not enc_postings:
            print('  no results')
            continue
        ids = decrypt_postings(enc_postings, priv)
        print('  Decrypted doc IDs:', ids)
        for doc_id in ids:
            print(f'   {doc_id}: {docs[doc_id]}')


if __name__ == '__main__':
    demo()
