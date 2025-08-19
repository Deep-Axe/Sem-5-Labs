import os
import time
import random
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class DiffieHellman:
    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.p = None  # Prime modulus
        self.g = None  # Generator
        self.private_key = None
        self.public_key = None
        self.shared_secret = None

    def generate_prime(self, bits):
        """Generate a prime number of specified bit length"""

        def is_prime(n, k=20):
            if n < 2:
                return False
            if n == 2 or n == 3:
                return True
            if n % 2 == 0:
                return False

            r = 0
            d = n - 1
            while d % 2 == 0:
                r += 1
                d //= 2

            for _ in range(k):
                a = random.randrange(2, n - 1)
                x = pow(a, d, n)
                if x == 1 or x == n - 1:
                    continue
                for _ in range(r - 1):
                    x = pow(x, 2, n)
                    if x == n - 1:
                        break
                else:
                    return False
            return True

        while True:
            n = random.getrandbits(bits)
            n |= (1 << bits - 1) | 1  # Ensure it's odd and has correct bit length
            if is_prime(n):
                return n

    def find_generator(self, p):
        """Find a generator for the given prime p"""
        # For simplicity, we'll use 2 as generator if valid, otherwise find one
        for g in range(2, min(100, p)):
            if pow(g, (p - 1) // 2, p) != 1:
                return g
        return 2

    def generate_parameters(self):
        """Generate DH parameters (p, g)"""
        print("Generating Diffie-Hellman parameters... This may take a moment...")
        start = time.time()

        # Generate a safe prime p = 2q + 1 where q is also prime
        while True:
            q = self.generate_prime(self.key_size - 1)
            p = 2 * q + 1
            if self.is_prime_simple(p):
                self.p = p
                break

        self.g = self.find_generator(self.p)
        elapsed = time.time() - start

        print(f"DH parameters generated in {elapsed:.3f} seconds")
        print(f"Prime (p): {self.p}")
        print(f"Generator (g): {self.g}")
        return elapsed

    def is_prime_simple(self, n):
        """Simple primality test for large numbers"""
        if n < 2:
            return False
        if n == 2:
            return True
        if n % 2 == 0:
            return False
        for i in range(3, int(n ** 0.5) + 1, 2):
            if n % i == 0:
                return False
        return True

    def generate_keypair(self):
        """Generate private and public keys"""
        if not self.p or not self.g:
            print("Generate DH parameters first!")
            return None

        start = time.time()
        # Private key: random number between 1 and p-2
        self.private_key = random.randrange(1, self.p - 1)
        # Public key: g^private_key mod p
        self.public_key = pow(self.g, self.private_key, self.p)
        elapsed = time.time() - start

        print(f"Keypair generated in {elapsed:.6f} seconds")
        return elapsed

    def compute_shared_secret(self, peer_public_key):
        """Compute shared secret using peer's public key"""
        if not self.private_key:
            print("Generate your keypair first!")
            return None

        start = time.time()
        self.shared_secret = pow(peer_public_key, self.private_key, self.p)
        elapsed = time.time() - start

        print(f"Shared secret computed in {elapsed:.6f} seconds")
        return elapsed

    def derive_encryption_key(self):
        """Derive AES key from shared secret"""
        if not self.shared_secret:
            return None

        # Use SHA-256 to derive a 256-bit AES key
        secret_bytes = self.shared_secret.to_bytes((self.shared_secret.bit_length() + 7) // 8, 'big')
        return hashlib.sha256(secret_bytes).digest()


def save_data(filename, data):
    """Save data to file"""
    with open(filename, 'w') as f:
        f.write(str(data))


def load_data(filename):
    """Load data from file"""
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            return int(f.read().strip())
    return None


def save_binary_data(filename, data):
    """Save binary data to file"""
    with open(filename, 'wb') as f:
        f.write(data)


def load_binary_data(filename):
    """Load binary data from file"""
    if os.path.exists(filename):
        with open(filename, 'rb') as f:
            return f.read()
    return None


def encrypt_file_aes(filename, outfile, key):
    """Encrypt file using AES-GCM"""
    start = time.time()

    # Read file data
    with open(filename, 'rb') as f:
        data = f.read()

    # Generate random IV
    iv = os.urandom(12)

    # Encrypt with AES-GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    tag = encryptor.tag

    # Save: IV + tag + ciphertext
    with open(outfile, 'wb') as f:
        f.write(iv)  # 12 bytes
        f.write(tag)  # 16 bytes
        f.write(ciphertext)

    elapsed = time.time() - start
    print(f"File encrypted in {elapsed:.3f} seconds")
    return elapsed


def decrypt_file_aes(filename, outfile, key):
    """Decrypt file using AES-GCM"""
    start = time.time()

    with open(filename, 'rb') as f:
        iv = f.read(12)
        tag = f.read(16)
        ciphertext = f.read()

    # Decrypt
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()

    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        with open(outfile, 'wb') as f:
            f.write(plaintext)

        elapsed = time.time() - start
        print(f"File decrypted in {elapsed:.3f} seconds")
        return elapsed
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None


def print_menu():
    print("\n==== Diffie-Hellman Key Exchange Menu ====")
    print("1. Generate DH Parameters (p, g)")
    print("2. Generate My Keypair")
    print("3. Export My Public Key")
    print("4. Import Peer's Public Key")
    print("5. Compute Shared Secret")
    print("6. Encrypt File with Shared Key")
    print("7. Decrypt File with Shared Key")
    print("8. Show Current Status")
    print("9. Performance Test")
    print("10. Exit")
    print("=========================================")


def performance_test(dh):
    """Run performance tests with different key sizes"""
    print("\n=== Performance Test ===")
    key_sizes = [1024, 2048]

    for size in key_sizes:
        print(f"\nTesting with {size}-bit keys:")
        test_dh = DiffieHellman(size)

        # Parameter generation
        param_time = test_dh.generate_parameters()

        # Key generation (Alice)
        alice_keygen_time = test_dh.generate_keypair()
        alice_public = test_dh.public_key

        # Key generation (Bob)
        bob_dh = DiffieHellman(size)
        bob_dh.p = test_dh.p
        bob_dh.g = test_dh.g
        bob_keygen_time = bob_dh.generate_keypair()
        bob_public = bob_dh.public_key

        # Shared secret computation
        alice_secret_time = test_dh.compute_shared_secret(bob_public)
        bob_secret_time = bob_dh.compute_shared_secret(alice_public)

        print(f"Parameter generation: {param_time:.3f}s")
        print(f"Alice key generation: {alice_keygen_time:.6f}s")
        print(f"Bob key generation: {bob_keygen_time:.6f}s")
        print(f"Alice secret computation: {alice_secret_time:.6f}s")
        print(f"Bob secret computation: {bob_secret_time:.6f}s")
        print(f"Secrets match: {test_dh.shared_secret == bob_dh.shared_secret}")


def main():
    dh = DiffieHellman()
    peer_public_key = None

    while True:
        print_menu()
        choice = input("Choice: ").strip()

        if choice == "1":
            dh.generate_parameters()
            # Save parameters
            save_data("dh_p.txt", dh.p)
            save_data("dh_g.txt", dh.g)

        elif choice == "2":
            if not dh.p or not dh.g:
                # Try to load existing parameters
                p = load_data("dh_p.txt")
                g = load_data("dh_g.txt")
                if p and g:
                    dh.p = p
                    dh.g = g
                    print("Loaded existing DH parameters")
                else:
                    print("Generate DH parameters first!")
                    continue

            dh.generate_keypair()
            # Save keys
            save_data("my_private_key.txt", dh.private_key)
            save_data("my_public_key.txt", dh.public_key)

        elif choice == "3":
            if not dh.public_key:
                print("Generate your keypair first!")
                continue

            filename = input("Export public key as filename: ").strip()
            save_data(filename, dh.public_key)
            print(f"Public key exported to {filename}")

        elif choice == "4":
            filename = input("Peer's public key filename: ").strip()
            peer_public_key = load_data(filename)
            if peer_public_key:
                print("Peer's public key loaded successfully")
            else:
                print("Failed to load peer's public key")

        elif choice == "5":
            if not peer_public_key:
                print("Import peer's public key first!")
                continue

            # Load our private key if not in memory
            if not dh.private_key:
                dh.private_key = load_data("my_private_key.txt")
                dh.p = load_data("dh_p.txt")
                if not dh.private_key or not dh.p:
                    print("Generate your keypair first!")
                    continue

            dh.compute_shared_secret(peer_public_key)
            print(f"Shared secret: {dh.shared_secret}")

        elif choice == "6":
            if not dh.shared_secret:
                print("Compute shared secret first!")
                continue

            infile = input("File to encrypt: ").strip()
            outfile = input("Output encrypted file: ").strip()

            aes_key = dh.derive_encryption_key()
            encrypt_file_aes(infile, outfile, aes_key)

        elif choice == "7":
            if not dh.shared_secret:
                print("Compute shared secret first!")
                continue

            infile = input("Encrypted file: ").strip()
            outfile = input("Output decrypted file: ").strip()

            aes_key = dh.derive_encryption_key()
            decrypt_file_aes(infile, outfile, aes_key)

        elif choice == "8":
            print(f"\n=== Current Status ===")
            print(f"DH Parameters: {'Set' if dh.p and dh.g else 'Not set'}")
            print(f"My Private Key: {'Set' if dh.private_key else 'Not set'}")
            print(f"My Public Key: {'Set' if dh.public_key else 'Not set'}")
            print(f"Peer Public Key: {'Set' if peer_public_key else 'Not set'}")
            print(f"Shared Secret: {'Computed' if dh.shared_secret else 'Not computed'}")

        elif choice == "9":
            performance_test(dh)

        elif choice == "10":
            print("Goodbye!")
            break

        else:
            print("Invalid choice!")


if __name__ == "__main__":
    main()