"""Simple Symmetric Searchable Encryption (SSE) demo.

Implements:
- Dataset: in-script list of 10+ documents (each with multiple words).
- AES-GCM encrypt/decrypt helpers for documents and index entries.
- Deterministic tokenization using HMAC-SHA256 over normalized words.
- Encrypted inverted index: token -> AES-GCM(encrypted posting list).
- Search: compute token from query, look up encrypted posting list, decrypt
  to get doc IDs, decrypt documents and display results.

This is an educational demo (not a production SSE system). It shows the
pattern: deterministic tokens (searchable) + encrypted postings (confidential).
"""
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import HMAC, SHA256
import json
import binascii
import os
import string


def generate_dataset():
    # 10 sample documents, each with several words
    docs = [
        "The quick brown fox jumps over the lazy dog",
        "Alice and Bob study cryptography and network security",
        "Symmetric encryption uses the same key for encrypt and decrypt",
        "Searchable encryption allows keyword searches over encrypted data",
        "Python is a popular programming language for security research",
        "Data structures include lists dictionaries sets and tuples",
        "The lab exercises cover AES RSA ECC and hashing algorithms",
        "Design patterns help build maintainable and testable software",
        "Fast hashing functions are used for checksums and bloom filters",
        "Homomorphic and functional encryption are advanced topics"
    ]
    return docs


def normalize(text: str) -> list:
    # Lowercase, remove punctuation, split on whitespace
    trans = str.maketrans('', '', string.punctuation)
    cleaned = text.translate(trans).lower()
    return [w for w in cleaned.split() if w]


class SSE:
    def __init__(self):
        # Keys
        self.doc_key = get_random_bytes(32)    # AES-256 for documents
        self.index_key = get_random_bytes(32)  # AES-256 for index posting encryption
        self.token_key = get_random_bytes(32)  # HMAC key for deterministic tokens

        # storage
        self.docs_enc = {}  # doc_id -> {nonce, ct}
        self.index_enc = {}  # token(hex) -> {nonce, ct}
        self.plain_docs = {}  # doc_id -> plaintext (kept for demo display)

    # AES-GCM helpers
    def encrypt_bytes(self, key: bytes, data: bytes) -> dict:
        aesgcm = AES.new(key, AES.MODE_GCM)
        ct, tag = aesgcm.encrypt_and_digest(data)
        return {'nonce': aesgcm.nonce, 'ct': ct, 'tag': tag}

    def decrypt_bytes(self, key: bytes, blob: dict) -> bytes:
        nonce = blob['nonce']
        ct = blob['ct']
        tag = blob['tag']
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ct, tag)

    # Documents
    def add_document(self, doc_id: int, text: str):
        pt = text.encode('utf-8')
        enc = self.encrypt_bytes(self.doc_key, pt)
        self.docs_enc[doc_id] = enc
        self.plain_docs[doc_id] = text

    def get_document(self, doc_id: int) -> str:
        enc = self.docs_enc[doc_id]
        pt = self.decrypt_bytes(self.doc_key, enc)
        return pt.decode('utf-8')

    # deterministic token (HMAC-SHA256) -> hex
    def token_for_word(self, word: str) -> str:
        h = HMAC.new(self.token_key, digestmod=SHA256)
        h.update(word.encode('utf-8'))
        return h.hexdigest()

    # index posting encryption (store list of ints as JSON bytes)
    def encrypt_postings(self, postings: list) -> dict:
        data = json.dumps(postings).encode('utf-8')
        return self.encrypt_bytes(self.index_key, data)

    def decrypt_postings(self, blob: dict) -> list:
        pt = self.decrypt_bytes(self.index_key, blob)
        return json.loads(pt.decode('utf-8'))

    def build_index(self, docs: list):
        raw_index = {}
        for doc_id, text in enumerate(docs):
            words = normalize(text)
            for w in words:
                token = self.token_for_word(w)
                raw_index.setdefault(token, set()).add(doc_id)

        # encrypt posting lists
        for token, s in raw_index.items():
            postings = sorted(list(s))
            self.index_enc[token] = self.encrypt_postings(postings)

    def search(self, query: str) -> list:
        # single-word searches for simplicity; normalize similarly
        qwords = normalize(query)
        result_ids = set()
        for w in qwords:
            token = self.token_for_word(w)
            blob = self.index_enc.get(token)
            if not blob:
                continue
            postings = self.decrypt_postings(blob)
            result_ids.update(postings)
        return sorted(list(result_ids))


def demo():
    docs = generate_dataset()
    sse = SSE()

    # add docs
    for i, d in enumerate(docs):
        sse.add_document(i, d)

    # build encrypted index
    sse.build_index(docs)

    print('Dataset (doc_id -> plaintext):')
    for i, d in enumerate(docs):
        print(f'{i}: {d}')

    print('\nEncrypted index tokens (hex) and posting ciphertexts:')
    for t, blob in sse.index_enc.items():
        print(f'token={t} -> nonce={binascii.hexlify(blob["nonce"]).decode()}, ct_len={len(blob["ct"])}')

    # demo searches
    queries = [
        'encryption',
        'DES',
        'python',
        'searchable',
        'data',
        'homomorphic'
    ]

    print('\nSearch demo:')
    for q in queries:
        ids = sse.search(q)
        print(f"\nQuery: '{q}' -> doc IDs: {ids}")
        for doc_id in ids:
            pt = sse.get_document(doc_id)
            print(f'  {doc_id}: {pt}')


if __name__ == '__main__':
    demo()
