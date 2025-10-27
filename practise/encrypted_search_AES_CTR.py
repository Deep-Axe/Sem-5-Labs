"""Encrypted Cloud Storage with Searchable Access (AES-128 CTR + HMAC tokens)

Parts implemented:
- Part A: AES-128 CTR per-document encryption; store ciphertexts and metadata in-memory (and optionally persist to JSON).
- Part B: Encrypted index built from HMAC-SHA256 tokens (deterministic tokens per word).
- Part C: Client computes token for query term and sends token to server; server returns matching ciphertexts (no plaintext revealed).
- Part D: Adds 10 sample documents, measures search latency and evaluates index lookup accuracy.

Notes:
- This demo uses HMAC-SHA256 tokens derived from a shared token_key. The server stores only tokens, not plaintext words.
- Deterministic tokens leak equality (same word -> same token). This is a known trade-off for simple searchable encryption.
"""

import os
import json
import time
import base64
import re
import hmac
import hashlib
from typing import Dict, List, Tuple

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


NONWORD = re.compile(r"[^a-z0-9]+")


def normalize(text: str) -> List[str]:
    s = text.lower()
    s = NONWORD.sub(' ', s)
    return [w for w in s.split() if w]


def generate_keys() -> Tuple[bytes, bytes]:
    # content_key: AES-128
    content_key = get_random_bytes(16)
    # token_key: used to derive deterministic search tokens (HMAC key)
    token_key = get_random_bytes(32)
    return content_key, token_key


def encrypt_aes_ctr(aes_key: bytes, plaintext: bytes) -> Dict[str, str]:
    # AES-CTR with random nonce
    nonce = get_random_bytes(8)
    cipher = AES.new(aes_key, AES.MODE_CTR, nonce=nonce)
    ct = cipher.encrypt(plaintext)
    return {'nonce': base64.b64encode(nonce).decode('utf-8'), 'ct': base64.b64encode(ct).decode('utf-8')}


def decrypt_aes_ctr(aes_key: bytes, blob: Dict[str, str]) -> bytes:
    nonce = base64.b64decode(blob['nonce'])
    ct = base64.b64decode(blob['ct'])
    cipher = AES.new(aes_key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ct)


def token_for_word(word: str, token_key: bytes) -> str:
    # deterministic token via HMAC-SHA256
    return hmac.new(token_key, word.encode('utf-8'), hashlib.sha256).hexdigest()


class EncryptedSearchServer:
    def __init__(self):
        # store ciphertexts: doc_id -> blob
        self.docs: Dict[str, Dict[str, str]] = {}
        # encrypted index: token -> list of doc_ids
        self.index: Dict[str, List[str]] = {}
        # plain inverted index for evaluation only (not used in server ops)
        self._plaintext_index: Dict[str, List[str]] = {}

    def store_document(self, doc_id: str, ciphertext_blob: Dict[str, str], tokens: List[str], plaintext_tokens: List[str]):
        self.docs[doc_id] = ciphertext_blob
        for t in tokens:
            self.index.setdefault(t, [])
            if doc_id not in self.index[t]:
                self.index[t].append(doc_id)
        # only for evaluation
        for w in plaintext_tokens:
            self._plaintext_index.setdefault(w, [])
            if doc_id not in self._plaintext_index[w]:
                self._plaintext_index[w].append(doc_id)

    def search_by_token(self, token: str) -> List[str]:
        # returns list of doc_ids (server does not know the plaintext)
        return list(self.index.get(token, []))

    def fetch_ciphertext(self, doc_id: str) -> Dict[str, str]:
        return self.docs.get(doc_id)


def build_index_and_store(server: EncryptedSearchServer, docs: Dict[str, str], aes_key: bytes, token_key: bytes):
    for doc_id, text in docs.items():
        tokens = []
        plaintext_tokens = normalize(text)
        for w in set(plaintext_tokens):
            tokens.append(token_for_word(w, token_key))
        blob = encrypt_aes_ctr(aes_key, text.encode('utf-8'))
        server.store_document(doc_id, blob, tokens, plaintext_tokens)


def client_search_and_retrieve(server: EncryptedSearchServer, query: str, token_key: bytes, aes_key: bytes):
    token = token_for_word(query, token_key)
    start = time.perf_counter()
    doc_ids = server.search_by_token(token)
    lookup_time = time.perf_counter() - start
    results = []
    for did in doc_ids:
        blob = server.fetch_ciphertext(did)
        pt = decrypt_aes_ctr(aes_key, blob).decode('utf-8')
        results.append((did, pt))
    return results, lookup_time


def evaluate(server: EncryptedSearchServer, token_key: bytes, aes_key: bytes):
    # queries: words that are in docs and some that are not
    all_plain_tokens = list(server._plaintext_index.keys())
    present_queries = all_plain_tokens[:5]
    absent_queries = ['nonexistentword', 'foobar', 'xyz']
    queries = present_queries + absent_queries

    total_lookup = 0.0
    counts = 0
    correct = 0
    for q in queries:
        results, t = client_search_and_retrieve(server, q, token_key, aes_key)
        total_lookup += t
        counts += 1
        # evaluate accuracy: compare returned doc ids to plaintext index
        expected = set(server._plaintext_index.get(q, []))
        returned = set(did for did, _ in results)
        if expected == returned:
            correct += 1
        print(f"Query='{q}' -> returned {len(results)} docs, time={t*1000:.2f}ms, expected={len(expected)}")

    print('\nEvaluation summary:')
    print(f'Average lookup time: {total_lookup / max(1, counts) * 1000:.2f} ms')
    print(f'Index lookup accuracy: {correct}/{counts} ({correct/counts*100:.1f}%)')


def demo():
    # sample documents (10)
    sample_docs = {
        f'doc{i}': text for i, text in enumerate([
            'Cryptography is essential for secure systems',
            'Searchable encryption enables queries on encrypted data',
            'AES in CTR mode provides confidentiality with random nonce',
            'Deterministic tokens leak equality but enable search',
            'Homomorphic encryption allows computation on ciphertexts',
            'Privacy preserving analytics on medical records',
            'Patient data must be protected with strong encryption',
            'Cloud storage should encrypt data at rest and in transit',
            'Indexing encrypted data requires careful design',
            'Latency and accuracy are important metrics for search'
        ], 1)}

    aes_key, token_key = generate_keys()
    server = EncryptedSearchServer()
    build_index_and_store(server, sample_docs, aes_key, token_key)

    print('Stored 10 sample documents encrypted with AES-128 CTR.')
    print('Built encrypted index with HMAC-SHA256 tokens.')

    # run evaluation
    evaluate(server, token_key, aes_key)


if __name__ == '__main__':
    demo()
