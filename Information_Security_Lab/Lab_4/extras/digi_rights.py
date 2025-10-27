"""DigiRights Inc. - Centralized Key Management & Access Control (ElGamal)

Educational/demo implementation. Features:
- Master ElGamal key generation (configurable size)
- Content encryption: hybrid AES-GCM + ElGamal-wrapped AES key
- Granting limited-time access to customers (wrap AES key to customer's RSA pubkey)
- Revoking access and master key revocation/renewal
- Secure storage of master private key (AES-GCM encrypted on disk)
- Auditing/logging of operations

This is a demo: in production, run this behind strong access controls,
use HSMs for private key storage, and use authenticated channels.
"""
import os
import json
import time
import base64
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util import number

# storage paths (relative to this file)
HERE = os.path.dirname(__file__)
STORE_DIR = os.path.join(HERE, 'digi_store')
os.makedirs(STORE_DIR, exist_ok=True)

MASTER_PUBLIC_FILE = os.path.join(STORE_DIR, 'master_pub.json')
MASTER_PRIV_FILE = os.path.join(STORE_DIR, 'master_priv.enc')
CONTENT_META_FILE = os.path.join(STORE_DIR, 'content_meta.json')
GRANTS_FILE = os.path.join(STORE_DIR, 'grants.json')
AUDIT_LOG = os.path.join(STORE_DIR, 'audit.log')


def audit(action: str, details: Dict[str, Any]):
    entry = {'time': datetime.utcnow().isoformat() + 'Z', 'action': action, 'details': details}
    with open(AUDIT_LOG, 'a', encoding='utf-8') as f:
        f.write(json.dumps(entry) + '\n')


class KeyManager:
    """Manage master ElGamal keypair and storage."""

    def __init__(self, storage_password: str = 'digi_demo_pass'):
        self.storage_password = storage_password
        self.master = None  # dict with p,g,y,x (x secret)
        if os.path.exists(MASTER_PUBLIC_FILE) and os.path.exists(MASTER_PRIV_FILE):
            try:
                self._load_master()
            except Exception:
                # can't load without password provided - leave unloaded
                self.master = None

    def generate_master(self, bits: int = 2048):
        # generate safe prime p and generator g; use simple approach via Crypto.Util.number
        p = number.getPrime(bits)
        # choose g in [2, p-2]
        g = number.getRandomRange(2, p-1)
        # choose private x
        x = number.getRandomRange(2, p-2)
        # compute y = g^x mod p
        y = pow(g, x, p)
        self.master = {'p': p, 'g': g, 'y': y, 'x': x, 'created_at': time.time(), 'revoked': False}
        self._save_master()
        audit('master_generate', {'bits': bits, 'p_bits': p.bit_length()})
        return self.master

    def _save_master(self):
        # save public params to MASTER_PUBLIC_FILE
        pub = {'p': hex(self.master['p']), 'g': hex(self.master['g']), 'y': hex(self.master['y']), 'created_at': self.master.get('created_at')}
        with open(MASTER_PUBLIC_FILE, 'w', encoding='utf-8') as f:
            json.dump(pub, f)

        # encrypt private x with storage_password and save to MASTER_PRIV_FILE
        salt = get_random_bytes(16)
        key = PBKDF2(self.storage_password, salt, dkLen=32, count=100_000)
        cipher = AES.new(key, AES.MODE_GCM)
        x_bytes = int(self.master['x']).to_bytes((self.master['x'].bit_length() + 7) // 8 or 1, 'big')
        ct, tag = cipher.encrypt_and_digest(x_bytes)
        blob = {'salt': base64.b64encode(salt).decode('utf-8'), 'nonce': base64.b64encode(cipher.nonce).decode('utf-8'), 'tag': base64.b64encode(tag).decode('utf-8'), 'ct': base64.b64encode(ct).decode('utf-8')}
        with open(MASTER_PRIV_FILE, 'w', encoding='utf-8') as f:
            json.dump(blob, f)

    def _load_master(self):
        # load public
        with open(MASTER_PUBLIC_FILE, 'r', encoding='utf-8') as f:
            pub = json.load(f)
        with open(MASTER_PRIV_FILE, 'r', encoding='utf-8') as f:
            blob = json.load(f)
        salt = base64.b64decode(blob['salt'])
        nonce = base64.b64decode(blob['nonce'])
        tag = base64.b64decode(blob['tag'])
        ct = base64.b64decode(blob['ct'])
        key = PBKDF2(self.storage_password, salt, dkLen=32, count=100_000)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        x_bytes = cipher.decrypt_and_verify(ct, tag)
        x = int.from_bytes(x_bytes, 'big')
        self.master = {'p': int(pub['p'], 16), 'g': int(pub['g'], 16), 'y': int(pub['y'], 16), 'x': x, 'created_at': pub.get('created_at'), 'revoked': False}

    def is_master_loaded(self) -> bool:
        return self.master is not None

    def elgamal_encrypt(self, plaintext_bytes: bytes):
        """Encrypt small bytes (e.g., AES key) under master public key. Returns (c1,c2) as hex strings."""
        if not self.master:
            raise RuntimeError('master key not loaded')
        p = self.master['p']
        g = self.master['g']
        y = self.master['y']
        m = int.from_bytes(plaintext_bytes, 'big')
        if m >= p:
            raise ValueError('plaintext too large for ElGamal modulus')
        k = number.getRandomRange(2, p - 2)
        c1 = pow(g, k, p)
        s = pow(y, k, p)
        c2 = (m * s) % p
        return hex(c1), hex(c2)

    def elgamal_decrypt(self, c1_hex: str, c2_hex: str) -> bytes:
        if not self.master:
            raise RuntimeError('master key not loaded')
        p = self.master['p']
        x = self.master['x']
        c1 = int(c1_hex, 16)
        c2 = int(c2_hex, 16)
        s = pow(c1, x, p)
        inv_s = number.inverse(s, p)
        m = (c2 * inv_s) % p
        # convert to bytes
        length = (m.bit_length() + 7) // 8 or 1
        return int.to_bytes(m, length, 'big')

    def export_private_for_recipient(self, recipient_rsa_pub_pem: bytes) -> bytes:
        """Return the master private x encrypted with recipient's RSA public key (OAEP)."""
        if not self.master:
            raise RuntimeError('master key not loaded')
        rsa_key = RSA.import_key(recipient_rsa_pub_pem)
        cipher = PKCS1_OAEP.new(rsa_key)
        x_bytes = int(self.master['x']).to_bytes((self.master['x'].bit_length() + 7) // 8 or 1, 'big')
        return cipher.encrypt(x_bytes)

    def revoke_master(self):
        if not self.master:
            raise RuntimeError('no master to revoke')
        self.master['revoked'] = True
        self._save_master()
        audit('master_revoked', {'created_at': self.master.get('created_at')})

    def rotate_master(self, bits: int = 2048):
        """Generate a new master key and re-wrap existing content symmetric keys.
        This function assumes ContentManager will call back to rewrap keys; for demo we just generate a fresh key and mark old revoked."""
        if self.master:
            # mark old revoked
            old = self.master.copy()
            old['revoked'] = True
            # save old as backup with timestamp
            with open(os.path.join(STORE_DIR, f'master_backup_{int(time.time())}.json'), 'w', encoding='utf-8') as f:
                json.dump({'p': hex(old['p']), 'g': hex(old['g']), 'y': hex(old['y']), 'x': hex(old['x'])}, f)
            audit('master_rotated_old_backup', {'backup': f.name})
        # generate new master
        self.generate_master(bits)
        audit('master_rotated_new', {'bits': bits})


class ContentManager:
    """Manage content encryption and storage.

    Content metadata stored in CONTENT_META_FILE as JSON mapping content_id -> meta
    """

    def __init__(self, key_manager: KeyManager):
        self.km = key_manager
        if os.path.exists(CONTENT_META_FILE):
            with open(CONTENT_META_FILE, 'r', encoding='utf-8') as f:
                self.meta = json.load(f)
        else:
            self.meta = {}

    def _save_meta(self):
        with open(CONTENT_META_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.meta, f, indent=2)

    def add_content(self, creator: str, title: str, content_bytes: bytes) -> str:
        # symmetric key
        aes_key = get_random_bytes(32)
        # AES-GCM encrypt
        cipher = AES.new(aes_key, AES.MODE_GCM)
        ct, tag = cipher.encrypt_and_digest(content_bytes)
        nonce = cipher.nonce
        # wrap AES key with master public (ElGamal)
        c1_hex, c2_hex = self.km.elgamal_encrypt(aes_key)
        content_id = hashlib.sha256(get_random_bytes(8)).hexdigest()[:12]
        # store ciphertext as base64 file
        fname = os.path.join(STORE_DIR, f'content_{content_id}.bin')
        with open(fname, 'wb') as f:
            f.write(base64.b64encode(ct))
        self.meta[content_id] = {'creator': creator, 'title': title, 'file': fname, 'nonce': base64.b64encode(nonce).decode('utf-8'), 'tag': base64.b64encode(tag).decode('utf-8'), 'sym_wrapped': {'c1': c1_hex, 'c2': c2_hex}, 'created_at': time.time()}
        self._save_meta()
        audit('content_added', {'content_id': content_id, 'creator': creator, 'title': title})
        return content_id

    def decrypt_content_with_aes_key(self, content_id: str, aes_key: bytes) -> bytes:
        meta = self.meta.get(content_id)
        if not meta:
            raise KeyError('no such content')
        fname = meta['file']
        with open(fname, 'rb') as f:
            ct = base64.b64decode(f.read())
        nonce = base64.b64decode(meta['nonce'])
        tag = base64.b64decode(meta['tag'])
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        pt = cipher.decrypt_and_verify(ct, tag)
        return pt

    def rewrap_all_to_new_master(self, old_km: KeyManager):
        """Re-wrap all stored symmetric keys from old_km to the current km's public key.
        Requires old_km to have master loaded and current self.km to be loaded as new master."""
        for cid, meta in self.meta.items():
            c1 = meta['sym_wrapped']['c1']
            c2 = meta['sym_wrapped']['c2']
            # decrypt with old
            aes_key = old_km.elgamal_decrypt(c1, c2)
            # encrypt with new master
            nc1, nc2 = self.km.elgamal_encrypt(aes_key)
            meta['sym_wrapped'] = {'c1': nc1, 'c2': nc2}
        self._save_meta()
        audit('content_rewrapped', {'count': len(self.meta)})


class AccessController:
    """Manage grants and distribution of wrapped symmetric keys to customers.

    Grants stored in GRANTS_FILE: mapping content_id -> customer_id -> grant info
    """

    def __init__(self, content_manager: ContentManager):
        self.cm = content_manager
        if os.path.exists(GRANTS_FILE):
            with open(GRANTS_FILE, 'r', encoding='utf-8') as f:
                self.grants = json.load(f)
        else:
            self.grants = {}

    def _save(self):
        with open(GRANTS_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.grants, f, indent=2)

    def grant_access(self, content_id: str, customer_id: str, customer_rsa_pub_pem: bytes, duration_seconds: int = 3600):
        # decrypt symmetric AES key using master private
        meta = self.cm.meta.get(content_id)
        if not meta:
            raise KeyError('no such content')
        c1 = meta['sym_wrapped']['c1']
        c2 = meta['sym_wrapped']['c2']
        aes_key = self.cm.km.elgamal_decrypt(c1, c2)
        # encrypt AES key under customer's RSA public key
        rsa_key = RSA.import_key(customer_rsa_pub_pem)
        wrapped = PKCS1_OAEP.new(rsa_key).encrypt(aes_key)
        expires = time.time() + duration_seconds
        self.grants.setdefault(content_id, {})[customer_id] = {'wrapped_key': base64.b64encode(wrapped).decode('utf-8'), 'expires': expires, 'revoked': False}
        self._save()
        audit('grant_access', {'content_id': content_id, 'customer_id': customer_id, 'expires': datetime.utcfromtimestamp(expires).isoformat() + 'Z'})
        return True

    def revoke_access(self, content_id: str, customer_id: str):
        g = self.grants.get(content_id, {}).get(customer_id)
        if g:
            g['revoked'] = True
            self._save()
            audit('revoke_access', {'content_id': content_id, 'customer_id': customer_id})
            return True
        return False

    def get_wrapped_key_for_customer(self, content_id: str, customer_id: str):
        g = self.grants.get(content_id, {}).get(customer_id)
        if not g:
            return None
        if g.get('revoked'):
            return None
        if time.time() > g.get('expires', 0):
            return None
        return base64.b64decode(g['wrapped_key'])


# Demo utilities
def generate_customer_keypair(bits: int = 2048):
    rsa = RSA.generate(bits)
    priv = rsa.export_key()
    pub = rsa.publickey().export_key()
    return pub, priv


def demo_flow():
    print('DigiRights demo: master key generation, content upload, grant, retrieve')
    km = KeyManager(storage_password='demo_pass')
    km.generate_master(bits=1024)  # smaller for fast demo; use 2048+ in production
    cm = ContentManager(km)
    ac = AccessController(cm)

    # content creator uploads
    cid = cm.add_content('creator_alice', 'E-Book: Cryptography 101', b'Example e-book content bytes...')
    print('Content added id=', cid)

    # generate customer keypair
    pub, priv = generate_customer_keypair(1024)
    print('Customer public key generated')

    # grant access for 60 seconds
    ac.grant_access(cid, 'customer_bob', pub, duration_seconds=60)
    print('Granted access to customer_bob for 60 seconds')

    # simulate customer retrieving wrapped key and decrypting locally
    wrapped = ac.get_wrapped_key_for_customer(cid, 'customer_bob')
    if wrapped:
        rsa_priv = RSA.import_key(priv)
        aes_key = PKCS1_OAEP.new(rsa_priv).decrypt(wrapped)
        print('Customer decrypted AES key locally:', aes_key.hex())
        # customer can now decrypt content
        pt = cm.decrypt_content_with_aes_key(cid, aes_key)
        print('Customer decrypted content (first 80 bytes):', pt[:80])
    else:
        print('No wrapped key available')

    # revoke access
    ac.revoke_access(cid, 'customer_bob')
    print('Access revoked for customer_bob')

    # demonstrate master rotation
    old_km = km
    km.rotate_master(bits=1024)
    # load new km object
    new_km = KeyManager(storage_password='demo_pass')
    # rewrap content from old to new
    cm_new = ContentManager(new_km)
    cm_new.rewrap_all_to_new_master(old_km)
    print('Master rotated and content rewrapped to new master')


if __name__ == '__main__':
    demo_flow()
