import os
import json
import logging
import secrets
from datetime import datetime, timedelta

# --- Rabin Cryptosystem Implementation ---
def is_prime(n):
    """Check for primality (inefficient, for demo only)."""
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

def generate_large_prime(bits):
    """Generate a large prime congruent to 3 mod 4."""
    while True:
        p = secrets.randbits(bits)
        p |= (1 << bits - 1) | 1  # Ensure p is odd & correct size
        if p % 4 != 3:
            continue
        if is_prime(p):
            return p

def rabin_keygen(bits=1024):
    """Generate Rabin key pair."""
    p = generate_large_prime(bits // 2)
    q = generate_large_prime(bits // 2)
    n = p * q
    return {'public': {'n': n}, 'private': {'p': p, 'q': q}}

# --- Key Management Service ---
class KeyManagementService:
    def __init__(self, db_file='kms_db.json', log_file='kms.log'):
        self.db_file = db_file
        self.keys = self.load_db()
        logging.basicConfig(filename=log_file, level=logging.INFO)

    def load_db(self):
        if os.path.exists(self.db_file):
            with open(self.db_file, 'r') as f:
                return json.load(f)
        return {}

    def save_db(self):
        with open(self.db_file, 'w') as f:
            json.dump(self.keys, f, indent=2)

    def log(self, action, entity, msg=''):
        log_entry = f"{datetime.now()} | {action} | {entity} | {msg}"
        logging.info(log_entry)

    def generate_keypair(self, entity, bits=1024):
        if entity in self.keys and not self.keys[entity].get('revoked', False):
            return "Key already exists and is active."
        keypair = rabin_keygen(bits)
        self.keys[entity] = {
            'public': keypair['public'],
            'private': keypair['private'],
            'created_at': str(datetime.now()),
            'renew_at': str(datetime.now() + timedelta(days=365)),
            'revoked': False
        }
        self.save_db()
        self.log("KEY_GENERATED", entity)
        return "Key pair generated for " + entity

    def distribute_keys(self, entity):
        if entity not in self.keys or self.keys[entity]['revoked']:
            return "No active key found."
        # In production, encrypt and securely deliver the private key!
        self.log("KEY_DISTRIBUTED", entity)
        return {
            "public": self.keys[entity]['public'],
            "private": self.keys[entity]['private']
        }

    def revoke_key(self, entity):
        if entity not in self.keys or self.keys[entity]['revoked']:
            return "No active key found."
        self.keys[entity]['revoked'] = True
        self.save_db()
        self.log("KEY_REVOKED", entity)
        return "Key revoked for " + entity

    def renew_key(self, entity, bits=1024):
        if entity not in self.keys or self.keys[entity]['revoked']:
            return "No active key found."
        keypair = rabin_keygen(bits)
        self.keys[entity]['public'] = keypair['public']
        self.keys[entity]['private'] = keypair['private']
        self.keys[entity]['renew_at'] = str(datetime.now() + timedelta(days=365))
        self.save_db()
        self.log("KEY_RENEWED", entity)
        return "Key renewed for " + entity

    def audit_log(self):
        with open('kms.log', 'r') as f:
            return f.read()

# --- Command-line Interface ---
def cli():
    kms = KeyManagementService()
    while True:
        print("\n--- HealthCare Inc. KMS ---")
        print("1. Generate Key Pair")
        print("2. Distribute Keys")
        print("3. Revoke Key")
        print("4. Renew Key")
        print("5. View Audit Log")
        print("6. Trade-off Analysis Rabin vs RSA")
        print("7. Exit")
        choice = input("Choose an option: ")
        if choice == '1':
            entity = input("Enter hospital/clinic name: ")
            bits = int(input("Key size in bits (default 1024): ") or "1024")
            print(kms.generate_keypair(entity, bits))
        elif choice == '2':
            entity = input("Enter hospital/clinic name: ")
            keys = kms.distribute_keys(entity)
            print(keys)
        elif choice == '3':
            entity = input("Enter hospital/clinic name: ")
            print(kms.revoke_key(entity))
        elif choice == '4':
            entity = input("Enter hospital/clinic name: ")
            bits = int(input("Key size in bits (default 1024): ") or "1024")
            print(kms.renew_key(entity, bits))
        elif choice == '5':
            print(kms.audit_log())
        elif choice == '6':
            print(tradeoff_analysis())
        elif choice == '7':
            break
        else:
            print("Invalid option.")

def tradeoff_analysis():
    return (
        "\n--- Rabin vs RSA Trade-off Analysis ---\n"
        "1. Security:\n"
        "   - Rabin: Security is provably as hard as factoring integers, but encryption produces 4 possible plaintexts.\n"
        "   - RSA: Widely used, security based on integer factorization, but not provably equivalent.\n"
        "2. Performance:\n"
        "   - Rabin: Encryption/Decryption is generally faster than RSA for equivalent key sizes.\n"
        "   - RSA: Slightly slower, but more flexible (encryption, signatures).\n"
        "3. Practicality:\n"
        "   - Rabin: Less common, rarely used in practice due to 4-to-1 mapping issue.\n"
        "   - RSA: Standard for public-key cryptography, libraries widely available.\n"
        "4. Applications:\n"
        "   - Rabin: Good for encrypting data, not for digital signatures.\n"
        "   - RSA: Supports encryption, signatures, key exchange.\n"
        "5. Conclusion:\n"
        "   - Rabin is theoretically stronger, but RSA is more practical for most real-world applications.\n"
    )

if __name__ == '__main__':
    cli()