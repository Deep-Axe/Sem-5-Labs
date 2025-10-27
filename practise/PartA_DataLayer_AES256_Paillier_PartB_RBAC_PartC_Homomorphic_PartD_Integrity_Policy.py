"""
Practise demo — Parts A/B/C/D:

Scenario summary (also encoded in file name):
- Part A (Data Layer):
  - Encrypt sensitive fields using AES-256 (AES-GCM) per-record.
  - Encrypt numerical fields (age, blood_pressure) using Paillier for additive homomorphic operations.
- Part B (Role-Based Access):
  - Only Project Leads can obtain AES data decryption keys (AES keys wrapped under Project Lead RSA pubkey).
  - Researchers can only perform homomorphic computations on Paillier ciphertexts; they cannot decrypt AES fields.
- Part C (Computation):
  - Support homomorphic summation of Paillier-encrypted numeric values and compute averages.
- Part D (Integrity & Policy Enforcement):
  - All operations produce an audit entry signed by the performing role.
  - Unauthorized decryption attempts are denied and logged (signed by an enforcement key).

"""

import os
import json
import base64
import math
import time
from datetime import datetime
from typing import Dict, Any, List, Tuple

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util import number
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


STORE = os.path.join(os.path.dirname(__file__), 'practise_store')
os.makedirs(STORE, exist_ok=True)
AUDIT_LOG = os.path.join(STORE, 'audit.log')
DATA_STORE = os.path.join(STORE, 'data.json')


def audit_log(entry: Dict[str, Any], signer_priv: RSA.RsaKey = None):
    """Append an audit entry (optional signature by signer_priv)."""
    entry['time'] = datetime.utcnow().isoformat() + 'Z'
    if signer_priv:
        h = SHA256.new(json.dumps(entry, sort_keys=True).encode('utf-8'))
        sig = pkcs1_15.new(signer_priv).sign(h)
        entry['signature'] = base64.b64encode(sig).decode('utf-8')
    with open(AUDIT_LOG, 'a', encoding='utf-8') as f:
        f.write(json.dumps(entry) + '\n')


class PaillierPub:
    def __init__(self, n: int, g: int):
        self.n = n
        self.g = g


class PaillierPriv:
    def __init__(self, p: int, q: int, lam: int, mu: int, n: int):
        self.p = p
        self.q = q
        self.lam = lam
        self.mu = mu
        self.n = n


def paillier_keygen(bits: int = 512) -> Tuple[PaillierPub, PaillierPriv]:
    # educational/simple implementation (use libraries for production)
    p = number.getPrime(bits // 2)
    q = number.getPrime(bits // 2)
    while q == p:
        q = number.getPrime(bits // 2)
    n = p * q
    nsq = n * n
    g = n + 1
    lam = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)

    def L(u):
        return (u - 1) // n

    x = pow(g, lam, nsq)
    mu = pow(L(x), -1, n)
    return PaillierPub(n, g), PaillierPriv(p, q, lam, mu, n)


def paillier_encrypt(pub: PaillierPub, m: int) -> int:
    n = pub.n
    nsq = n * n
    if not (0 <= m < n):
        raise ValueError('plaintext out of range')
    while True:
        r = number.getRandomRange(1, n)
        if math.gcd(r, n) == 1:
            break
    c = (pow(pub.g, m, nsq) * pow(r, n, nsq)) % nsq
    return c


def paillier_decrypt(priv: PaillierPriv, c: int) -> int:
    n = priv.n
    nsq = n * n

    def L(u):
        return (u - 1) // n

    x = pow(c, priv.lam, nsq)
    m = (L(x) * priv.mu) % n
    return m


def paillier_add(pub: PaillierPub, c1: int, c2: int) -> int:
    nsq = pub.n * pub.n
    return (c1 * c2) % nsq


class AESHelper:
    @staticmethod
    def encrypt(key: bytes, data: bytes) -> Dict[str, str]:
        cipher = AES.new(key, AES.MODE_GCM)
        ct, tag = cipher.encrypt_and_digest(data)
        return {'nonce': base64.b64encode(cipher.nonce).decode('utf-8'), 'ct': base64.b64encode(ct).decode('utf-8'), 'tag': base64.b64encode(tag).decode('utf-8')}

    @staticmethod
    def decrypt(key: bytes, blob: Dict[str, str]) -> bytes:
        nonce = base64.b64decode(blob['nonce'])
        ct = base64.b64decode(blob['ct'])
        tag = base64.b64decode(blob['tag'])
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ct, tag)


class Role:
    def __init__(self, name: str, bits: int = 2048):
        self.name = name
        self.rsa = RSA.generate(bits)

    def pub_pem(self) -> bytes:
        return self.rsa.publickey().export_key()

    def sign(self, obj: Dict[str, Any]) -> bytes:
        h = SHA256.new(json.dumps(obj, sort_keys=True).encode('utf-8'))
        return pkcs1_15.new(self.rsa).sign(h)

    def verify(self, obj: Dict[str, Any], sig: bytes) -> bool:
        h = SHA256.new(json.dumps(obj, sort_keys=True).encode('utf-8'))
        try:
            pkcs1_15.new(self.rsa.publickey()).verify(h, sig)
            return True
        except Exception:
            return False


class AccessControl:
    """Enforce that only ProjectLead can unwrap AES content keys. Researchers can't."""

    def __init__(self, project_lead: Role, enforcement_role: Role):
        self.project_lead = project_lead
        self.enforcer = enforcement_role

    def can_decrypt_aes(self, role: Role) -> bool:
        return role.name == self.project_lead.name

    def attempt_decrypt_aes(self, role: Role, wrapped_key: bytes) -> Tuple[bool, bytes]:
        # wrapped_key is RSA-OAEP encrypted AES key under ProjectLead pub
        if not self.can_decrypt_aes(role):
            # log denial signed by enforcer
            entry = {'action': 'AES_DECRYPT_DENIED', 'role': role.name}
            audit_log(entry, self.enforcer.rsa)
            return False, b''
        # If role is project lead, they have RSA private key so unwrap
        priv = role.rsa
        aes_key = PKCS1_OAEP.new(priv).decrypt(wrapped_key)
        entry = {'action': 'AES_DECRYPT_OK', 'role': role.name}
        audit_log(entry, role.rsa)
        return True, aes_key


def save_data(records: List[Dict[str, Any]]):
    with open(DATA_STORE, 'w', encoding='utf-8') as f:
        json.dump(records, f, indent=2)


def load_data() -> List[Dict[str, Any]]:
    if not os.path.exists(DATA_STORE):
        return []
    with open(DATA_STORE, 'r', encoding='utf-8') as f:
        return json.load(f)


def demo():
    print('Demo: AES + Paillier data sharing with RBAC and signed audit logs')

    # Setup roles
    project_lead = Role('ProjectLead')
    researcher = Role('Researcher')
    data_owner = Role('DataOwner')
    enforcer = Role('Enforcer')

    ac = AccessControl(project_lead, enforcer)

    # Paillier keys (used for numeric fields)
    pub, priv = paillier_keygen(bits=512)
    audit_log({'action': 'paillier_keygen', 'n_bits': pub.n.bit_length()}, data_owner.rsa)

    # DataOwner prepares records: sensitive field 'name' (AES), numeric fields using Paillier
    records = []
    sample = [
        {'name': b'Alice Smith', 'age': 34, 'bp': 120},
        {'name': b'Bob Jones', 'age': 42, 'bp': 130},
        {'name': b'Carol Lee', 'age': 29, 'bp': 110},
    ]

    for rec in sample:
        # generate per-record AES key, wrap under ProjectLead RSA pub
        aes_key = get_random_bytes(32)  # AES-256
        aes_blob = AESHelper.encrypt(aes_key, rec['name'])
        # wrap AES key to ProjectLead
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(project_lead.pub_pem()))
        wrapped_key = cipher_rsa.encrypt(aes_key)
        # encrypt numeric fields with Paillier
        c_age = paillier_encrypt(pub, rec['age'])
        c_bp = paillier_encrypt(pub, rec['bp'])
        record = {'aes_blob': aes_blob, 'aes_wrapped_for': 'ProjectLead', 'aes_wrapped_key': base64.b64encode(wrapped_key).decode('utf-8'), 'age_ct': str(c_age), 'bp_ct': str(c_bp)}
        records.append(record)
        audit_log({'action': 'record_created', 'by': 'DataOwner', 'age_ct': record['age_ct']}, data_owner.rsa)

    save_data(records)
    print('Records stored. Researchers can operate on Paillier ciphertexts but cannot unwrap AES content.')

    # Researcher attempts to decrypt first record's AES field (should be denied)
    stored = load_data()
    first = stored[0]
    wrapped = base64.b64decode(first['aes_wrapped_key'])
    ok, aes_key = ac.attempt_decrypt_aes(researcher, wrapped)
    print('\nResearcher attempted AES decrypt ->', 'OK' if ok else 'DENIED')

    # Researcher performs homomorphic sum of ages
    age_cts = [int(r['age_ct']) for r in stored]
    sum_ct = age_cts[0]
    for c in age_cts[1:]:
        sum_ct = paillier_add(pub, sum_ct, c)
    audit_log({'action': 'homomorphic_sum', 'by': 'Researcher', 'sum_ct': str(sum_ct)}, researcher.rsa)
    print('\nResearcher computed homomorphic sum ciphertext (cannot decrypt locally).')

    # ProjectLead (or DataOwner) asks DataOwner (priv holder) to decrypt sum
    # For demo, DataOwner has Paillier priv 'priv'
    total = paillier_decrypt(priv, sum_ct)
    avg = total / len(stored)
    audit_log({'action': 'decrypt_sum', 'by': 'DataOwner', 'sum': int(total), 'avg': avg}, data_owner.rsa)
    print('Decrypted total age =', total, ', average =', avg)

    # Now ProjectLead requests AES unwrap and decryption of name
    ok2, aes_key2 = ac.attempt_decrypt_aes(project_lead, wrapped)
    if ok2:
        name = AESHelper.decrypt(aes_key2, first['aes_blob'])
        audit_log({'action': 'aes_decrypt', 'by': 'ProjectLead', 'name_decrypted': True}, project_lead.rsa)
        print('\nProjectLead decrypted name:', name)

    # Attempt an unauthorized decryption by Researcher (again) to show denial logging
    ok3, _ = ac.attempt_decrypt_aes(researcher, wrapped)
    print('\nSecond unauthorized attempt by Researcher ->', 'OK' if ok3 else 'DENIED')

    print('\nAudit log entries:')
    with open(AUDIT_LOG, 'r', encoding='utf-8') as f:
        for line in f:
            print(line.strip())


if __name__ == '__main__':
    demo()
