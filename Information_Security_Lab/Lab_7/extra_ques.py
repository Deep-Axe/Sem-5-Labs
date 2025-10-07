import random
import math
import time
from typing import Tuple, List
from sympy import isprime, primitive_root


class PaillierCryptosystem:
    """Implementation of the Paillier Cryptosystem for Homomorphic Encryption"""

    def __init__(self, key_size=512):
        """Initialize and generate keys for Paillier encryption"""
        self.public_key, self.private_key = self.generate_keypair(key_size)

    def generate_keypair(self, key_size):
        """
        Generates a public/private key pair for Paillier encryption

        Returns:
            public_key: (n, g) where n = p*q and g is generator
            private_key: (lambda, mu) for decryption
        """
        # Generate two large prime numbers p and q
        p = self._generate_prime(key_size // 2)
        q = self._generate_prime(key_size // 2)

        # Ensure p and q are different
        while p == q:
            q = self._generate_prime(key_size // 2)

        # Calculate n = p * q
        n = p * q

        # Calculate n^2
        n_squared = n * n

        # Calculate lambda = lcm(p-1, q-1)
        lambda_val = self._lcm(p - 1, q - 1)

        # Choose g = n + 1 (standard choice for simplicity)
        g = n + 1

        # Calculate mu = (L(g^lambda mod n^2))^-1 mod n
        # where L(x) = (x-1)/n
        g_lambda = pow(g, lambda_val, n_squared)
        l_value = self._L(g_lambda, n)
        mu = self._mod_inverse(l_value, n)

        public_key = (n, g)
        private_key = (lambda_val, mu, n)

        return public_key, private_key

    @staticmethod
    def _generate_prime(bits: int) -> int:
        """Generate a random prime number with a specified bit length"""
        while True:
            num = random.getrandbits(bits)
            # Ensure the number has the correct bit length
            num |= (1 << bits - 1) | 1  # Set MSB and LSB to 1
            if isprime(num):
                return num

    @staticmethod
    def _lcm(a, b):
        """Calculate the least common multiple"""
        return abs(a * b) // math.gcd(a, b)

    @staticmethod
    def _L(x: int, n: int) -> int:
        """L function: L(x) = (x-1)/n"""
        return (x - 1) // n

    @staticmethod
    def _mod_inverse(a, n):
        """Calculate modular multiplicative inverse using extended Euclidean algorithm"""
        return pow(a, -1, n)

    def encrypt(self, message):
        """
        Encrypts a message using the public key

        Args:
            message: Integer to encrypt

        Returns:
            ciphertext: Encrypted message
        """
        n, g = self.public_key
        n_squared = n * n

        # Generate random r where 0 < r < n and gcd(r, n) = 1
        while True:
            r = random.randint(1, n - 1)
            if math.gcd(r, n) == 1:
                break

        # Calculate ciphertext: c = g^m * r^n mod n^2
        ciphertext = (pow(g, message, n_squared) * pow(r, n, n_squared)) % n_squared

        return ciphertext

    def decrypt(self, ciphertext):
        """
        Decrypts a ciphertext using the private key

        Args:
            ciphertext: Encrypted message

        Returns:
            message: Decrypted integer
        """
        lambda_val, mu, n = self.private_key
        n_squared = n * n

        # Calculate m = L(c^lambda mod n^2) * mu mod n
        c_lambda = pow(ciphertext, lambda_val, n_squared)
        l_value = self._L(c_lambda, n)
        message = (l_value * mu) % n

        return message

    def homomorphic_add(self, ciphertext1, ciphertext2):
        """
        Performs homomorphic addition on two ciphertexts

        Args:
            ciphertext1: First encrypted message
            ciphertext2: Second encrypted message

        Returns:
            result: Encrypted sum of the two messages
        """
        n, g = self.public_key
        n_squared = n * n

        # Homomorphic addition: E(m1 + m2) = E(m1) * E(m2) mod n^2
        result = (ciphertext1 * ciphertext2) % n_squared

        return result

    def homomorphic_scalar_multiply(self, ciphertext, scalar):
        """
        Performs homomorphic scalar multiplication

        Args:
            ciphertext: Encrypted message
            scalar: Plaintext scalar to multiply

        Returns:
            result: Encrypted result of m * scalar
        """
        n, g = self.public_key
        n_squared = n * n

        # E(m * k) = E(m)^k mod n^2
        result = pow(ciphertext, scalar, n_squared)
        return result


class RSACryptosystem:
    """Implementation of RSA for Homomorphic Multiplication"""

    def __init__(self, key_size=512):
        """Initialize and generate keys for RSA encryption"""
        self.public_key, self.private_key = self.generate_keypair(key_size)

    def generate_keypair(self, key_size):
        """
        Generates a public/private key pair for RSA encryption

        Returns:
            public_key: (n, e)
            private_key: (n, d)
        """
        # Generate two large prime numbers p and q
        p = self._generate_prime(key_size // 2)
        q = self._generate_prime(key_size // 2)

        # Ensure p and q are different
        while p == q:
            q = self._generate_prime(key_size // 2)

        # Calculate n = p * q
        n = p * q

        # Calculate Euler's totient: phi(n) = (p-1)(q-1)
        phi_n = (p - 1) * (q - 1)

        # Choose public exponent e (commonly 65537)
        e = 65537
        while math.gcd(e, phi_n) != 1:
            e = random.randrange(2, phi_n)

        # Calculate private exponent d
        d = pow(e, -1, phi_n)

        public_key = (n, e)
        private_key = (n, d)

        return public_key, private_key

    @staticmethod
    def _generate_prime(bits: int) -> int:
        """Generate a random prime number with a specified bit length"""
        while True:
            num = random.getrandbits(bits)
            num |= (1 << bits - 1) | 1
            if isprime(num):
                return num

    def encrypt(self, message):
        """
        Encrypts a message using the public key

        Args:
            message: Integer to encrypt

        Returns:
            ciphertext: Encrypted message
        """
        n, e = self.public_key
        # c = m^e mod n
        ciphertext = pow(message, e, n)
        return ciphertext

    def decrypt(self, ciphertext):
        """
        Decrypts a ciphertext using the private key

        Args:
            ciphertext: Encrypted message

        Returns:
            message: Decrypted integer
        """
        n, d = self.private_key
        # m = c^d mod n
        message = pow(ciphertext, d, n)
        return message

    def homomorphic_multiply(self, ciphertext1, ciphertext2):
        """
        Performs homomorphic multiplication on two ciphertexts

        Args:
            ciphertext1: First encrypted message
            ciphertext2: Second encrypted message

        Returns:
            result: Encrypted product of the two messages
        """
        n, e = self.public_key
        # E(m1 * m2) = E(m1) * E(m2) mod n
        result = (ciphertext1 * ciphertext2) % n
        return result


class ElGamalCryptosystem:
    """Implementation of ElGamal for Homomorphic Multiplication"""

    def __init__(self, key_size=512):
        """Initialize and generate keys for ElGamal encryption"""
        self.public_key, self.private_key = self.generate_keypair(key_size)

    def generate_keypair(self, key_size):
        """
        Generates a public/private key pair for ElGamal encryption

        Returns:
            public_key: (p, g, h) where h = g^x mod p
            private_key: (p, x)
        """
        # Generate a large prime p
        p = self._generate_safe_prime(key_size)

        # Find a generator g of the multiplicative group mod p
        g = self._find_generator(p)

        # Choose private key x randomly from {1, ..., p-2}
        x = random.randint(1, p - 2)

        # Calculate public key h = g^x mod p
        h = pow(g, x, p)

        public_key = (p, g, h)
        private_key = (p, x)

        return public_key, private_key

    @staticmethod
    def _generate_safe_prime(bits: int) -> int:
        """Generate a safe prime p where p = 2q + 1 and q is also prime"""
        while True:
            q = random.getrandbits(bits - 1)
            q |= (1 << bits - 2) | 1
            if isprime(q):
                p = 2 * q + 1
                if isprime(p):
                    return p

    @staticmethod
    def _find_generator(p: int) -> int:
        """Find a generator of the multiplicative group mod p"""
        try:
            return primitive_root(p)
        except:
            # Fallback to small generator
            for g in range(2, min(100, p)):
                if pow(g, 2, p) != 1 and pow(g, (p - 1) // 2, p) != 1:
                    return g
            return 2

    def encrypt(self, message):
        """
        Encrypts a message using the public key

        Args:
            message: Integer to encrypt

        Returns:
            ciphertext: Tuple (c1, c2)
        """
        p, g, h = self.public_key

        # Choose random ephemeral key y
        y = random.randint(1, p - 2)

        # Calculate c1 = g^y mod p
        c1 = pow(g, y, p)

        # Calculate c2 = m * h^y mod p
        c2 = (message * pow(h, y, p)) % p

        return (c1, c2)

    def decrypt(self, ciphertext):
        """
        Decrypts a ciphertext using the private key

        Args:
            ciphertext: Tuple (c1, c2)

        Returns:
            message: Decrypted integer
        """
        p, x = self.private_key
        c1, c2 = ciphertext

        # Calculate s = c1^x mod p
        s = pow(c1, x, p)

        # Calculate s_inv = s^(-1) mod p
        s_inv = pow(s, -1, p)

        # Calculate m = c2 * s_inv mod p
        message = (c2 * s_inv) % p

        return message

    def homomorphic_multiply(self, ciphertext1, ciphertext2):
        """
        Performs homomorphic multiplication on two ciphertexts

        Args:
            ciphertext1: First encrypted message (c1_1, c2_1)
            ciphertext2: Second encrypted message (c1_2, c2_2)

        Returns:
            result: Encrypted product (c1_1 * c1_2, c2_1 * c2_2)
        """
        p, g, h = self.public_key
        c1_1, c2_1 = ciphertext1
        c1_2, c2_2 = ciphertext2

        # E(m1 * m2) = (c1_1 * c1_2 mod p, c2_1 * c2_2 mod p)
        result_c1 = (c1_1 * c1_2) % p
        result_c2 = (c2_1 * c2_2) % p

        return (result_c1, result_c2)





def test_rsa_multiplication():
    """Test RSA homomorphic multiplication"""


    print("\n[Step 1] Generating RSA key pair...")
    rsa = RSACryptosystem(key_size=512)
    print(" Key pair generated successfully!")

    # Define two integers to encrypt
    a = 7
    b = 3
    expected_product = a * b

    print(f"\n[Step 2] Original integers:")
    print(f"  a = {a}")
    print(f"  b = {b}")
    print(f"  Expected product (a × b) = {expected_product}")

    # Encrypt the integers
    print(f"\n[Step 3] Encrypting integers...")
    ciphertext_a = rsa.encrypt(a)
    ciphertext_b = rsa.encrypt(b)

    print(f"  Ciphertext of a (7): {ciphertext_a}")
    print(f"  Ciphertext of b (3): {ciphertext_b}")

    # Perform homomorphic multiplication
    print(f"\n[Step 4] Performing homomorphic multiplication...")
    ciphertext_product = rsa.homomorphic_multiply(ciphertext_a, ciphertext_b)
    print(f"  Ciphertext of (a × b): {ciphertext_product}")

    # Decrypt the result
    print(f"\n[Step 5] Decrypting the product...")
    decrypted_product = rsa.decrypt(ciphertext_product)
    print(f"  Decrypted product: {decrypted_product}")

    # Verify the result
    print(f"\n[Step 6] Verification:")
    print(f"  Expected product: {expected_product}")
    print(f"  Decrypted product: {decrypted_product}")

    if decrypted_product == expected_product:
        print("  SUCCESS: Homomorphic multiplication verified correctly!")
    else:
        print("  ERROR: Verification failed!")


def test_elgamal_multiplication():


    print("\n[Step 1] Generating ElGamal key pair...")
    elgamal = ElGamalCryptosystem(key_size=256)  # Smaller for speed
    print("Key pair generated successfully!")

    # Define two integers to encrypt
    a = 12
    b = 5
    expected_product = a * b

    print(f"\n[Step 2] Original integers:")
    print(f"  a = {a}")
    print(f"  b = {b}")
    print(f"  Expected product (a × b) = {expected_product}")

    # Encrypt the integers
    print(f"\n[Step 3] Encrypting integers...")
    ciphertext_a = elgamal.encrypt(a)
    ciphertext_b = elgamal.encrypt(b)

    print(f"  Ciphertext of a: {ciphertext_a}")
    print(f"  Ciphertext of b: {ciphertext_b}")

    # Perform homomorphic multiplication
    print(f"\n[Step 4] Performing homomorphic multiplication...")
    ciphertext_product = elgamal.homomorphic_multiply(ciphertext_a, ciphertext_b)
    print(f"  Ciphertext of (a × b): {ciphertext_product}")

    # Decrypt the result
    print(f"\n[Step 5] Decrypting the product...")
    decrypted_product = elgamal.decrypt(ciphertext_product)
    print(f"  Decrypted product: {decrypted_product}")

    # Verify the result
    print(f"\n[Step 6] Verification:")
    print(f"  Expected product: {expected_product}")
    print(f"  Decrypted product: {decrypted_product}")

    if decrypted_product == expected_product:
        print("   SUCCESS: ElGamal homomorphic multiplication verified!")
    else:
        print("   ERROR: Verification failed!")

    # Additional test with multiple multiplications
    print(f"\n[Additional Test] Multiple multiplications:")
    c = 2
    ciphertext_c = elgamal.encrypt(c)
    ciphertext_abc = elgamal.homomorphic_multiply(ciphertext_product, ciphertext_c)
    decrypted_abc = elgamal.decrypt(ciphertext_abc)

    print(f"  Computing {a} × {b} × {c} = {a * b * c}")
    print(f"  Decrypted result: {decrypted_abc}")
    print(f"  Verification: {decrypted_abc == a * b * c}")


def test_secure_data_sharing():


    print("\n[Scenario] Two hospitals want to compute total patient count")
    print("            without revealing individual hospital counts")

    print("\n[Step 1] Generating Paillier key pair...")
    paillier = PaillierCryptosystem(key_size=512)
    print("✓ Key pair generated!")

    # Hospital data
    hospital_a_patients = 150
    hospital_b_patients = 230
    expected_total = hospital_a_patients + hospital_b_patients

    print(f"\n[Step 2] Hospital data (private):")
    print(f"  Hospital A: {hospital_a_patients} patients")
    print(f"  Hospital B: {hospital_b_patients} patients")
    print(f"  Expected total: {expected_total} patients")

    # Each hospital encrypts their data
    print(f"\n[Step 3] Each hospital encrypts their patient count...")
    encrypted_a = paillier.encrypt(hospital_a_patients)
    encrypted_b = paillier.encrypt(hospital_b_patients)

    print(f"  Hospital A encrypted data: {encrypted_a}")
    print(f"  Hospital B encrypted data: {encrypted_b}")

    # Combine encrypted data without decryption
    print(f"\n[Step 4] Computing total on encrypted data...")
    encrypted_total = paillier.homomorphic_add(encrypted_a, encrypted_b)
    print(f"  Encrypted total: {encrypted_total}")

    # Only authorized party can decrypt
    print(f"\n[Step 5] Authorized party decrypts the total...")
    decrypted_total = paillier.decrypt(encrypted_total)
    print(f"  Total patients: {decrypted_total}")

    print(f"\n[Step 6] Verification:")
    if decrypted_total == expected_total:
        print(f"   SUCCESS: Total matches ({decrypted_total} = {expected_total})")
        print(f"   Individual hospital data remained private!")
    else:
        print(f"  ERROR: Verification failed!")

    # Demonstrate weighted average scenario
    print(f"\n[Additional Scenario] Weighted contributions:")
    print(f"  Hospital A contributes 2x their count")
    print(f"  Hospital B contributes 3x their count")

    encrypted_weighted_a = paillier.homomorphic_scalar_multiply(encrypted_a, 2)
    encrypted_weighted_b = paillier.homomorphic_scalar_multiply(encrypted_b, 3)
    encrypted_weighted_total = paillier.homomorphic_add(encrypted_weighted_a, encrypted_weighted_b)

    weighted_total = paillier.decrypt(encrypted_weighted_total)
    expected_weighted = 2 * hospital_a_patients + 3 * hospital_b_patients

    print(f"  Computed weighted total: {weighted_total}")
    print(f"  Expected: {expected_weighted}")
    print(f"  Verification: {weighted_total == expected_weighted}")


def test_secure_thresholding():


    print("\n[Scenario] 3 parties want to compute average salary")
    print("            Only reveal result if all 3 parties participate")

    print("\n[Step 1] Generating Paillier key pair for trusted third party...")
    paillier = PaillierCryptosystem(key_size=512)
    print("✓ Key pair generated!")

    # Party data
    salaries = {
        "Party A": 75000,
        "Party B": 82000,
        "Party C": 68000
    }
    num_parties = len(salaries)
    expected_sum = sum(salaries.values())
    expected_average = expected_sum // num_parties

    print(f"\n[Step 2] Private party data:")
    for party, salary in salaries.items():
        print(f"  {party}: ${salary:,}")
    print(f"  Expected sum: ${expected_sum:,}")
    print(f"  Expected average: ${expected_average:,}")

    # Each party encrypts their salary
    print(f"\n[Step 3] Each party encrypts their salary...")
    encrypted_salaries = {}
    for party, salary in salaries.items():
        encrypted_salaries[party] = paillier.encrypt(salary)
        print(f"  {party} encrypted: {encrypted_salaries[party]}")

    # Combine all encrypted salaries
    print(f"\n[Step 4] Computing total on encrypted data...")
    encrypted_total = encrypted_salaries["Party A"]
    for party in ["Party B", "Party C"]:
        encrypted_total = paillier.homomorphic_add(encrypted_total, encrypted_salaries[party])

    print(f"  Encrypted total: {encrypted_total}")

    # Decrypt total
    print(f"\n[Step 5] Decrypting total...")
    decrypted_total = paillier.decrypt(encrypted_total)
    print(f"  Total salary: ${decrypted_total:,}")

    # Calculate average
    average_salary = decrypted_total // num_parties
    print(f"  Average salary: ${average_salary:,}")

    print(f"\n[Step 6] Verification:")
    if decrypted_total == expected_sum and average_salary == expected_average:
        print(f"  SUCCESS: Computation correct!")
        print(f"  Individual salaries remained private!")
    else:
        print(f"  ERROR: Verification failed!")

    # Demonstrate threshold requirement
    print(f"\n[Threshold Scenario] What if only 2 parties participate?")
    encrypted_partial = paillier.homomorphic_add(
        encrypted_salaries["Party A"],
        encrypted_salaries["Party B"]
    )
    partial_sum = paillier.decrypt(encrypted_partial)
    print(f"  Partial sum (A + B): ${partial_sum:,}")
    print(f"  ⚠ This is incomplete - requires all {num_parties} parties!")

    # Simulate voting threshold
    print(f"\n[Voting Scenario] Secure vote counting:")
    votes = {"Voter 1": 1, "Voter 2": 1, "Voter 3": 0, "Voter 4": 1, "Voter 5": 1}
    encrypted_votes = [paillier.encrypt(v) for v in votes.values()]

    encrypted_vote_total = encrypted_votes[0]
    for enc_vote in encrypted_votes[1:]:
        encrypted_vote_total = paillier.homomorphic_add(encrypted_vote_total, enc_vote)

    total_yes_votes = paillier.decrypt(encrypted_vote_total)
    print(f"  Total 'Yes' votes: {total_yes_votes}/{len(votes)}")
    print(f"  Result: {'PASSED' if total_yes_votes >= 3 else 'FAILED'} (threshold: 3)")


def test_performance_analysis():


    key_sizes = [256, 512]
    num_operations = 10

    results = {
        'Paillier': {'keygen': [], 'encrypt': [], 'decrypt': [], 'homo_op': []},
        'RSA': {'keygen': [], 'encrypt': [], 'decrypt': [], 'homo_op': []},
        'ElGamal': {'keygen': [], 'encrypt': [], 'decrypt': [], 'homo_op': []}
    }

    for key_size in key_sizes:
        print(f"\n{'='*80}")
        print(f"Testing with key size: {key_size} bits")
        print(f"{'='*80}")

        # Test Paillier
        print(f"\n[Paillier Cryptosystem]")
        start = time.time()
        paillier = PaillierCryptosystem(key_size=key_size)
        keygen_time = time.time() - start
        results['Paillier']['keygen'].append(keygen_time)
        print(f"  Key generation: {keygen_time:.4f}s")

        # Encryption benchmark
        message = 42
        start = time.time()
        for _ in range(num_operations):
            enc = paillier.encrypt(message)
        encrypt_time = (time.time() - start) / num_operations
        results['Paillier']['encrypt'].append(encrypt_time)
        print(f"  Encryption (avg): {encrypt_time:.6f}s")

        # Decryption benchmark
        start = time.time()
        for _ in range(num_operations):
            dec = paillier.decrypt(enc)
        decrypt_time = (time.time() - start) / num_operations
        results['Paillier']['decrypt'].append(decrypt_time)
        print(f"  Decryption (avg): {decrypt_time:.6f}s")

        # Homomorphic addition benchmark
        enc1 = paillier.encrypt(10)
        enc2 = paillier.encrypt(20)
        start = time.time()
        for _ in range(num_operations):
            result = paillier.homomorphic_add(enc1, enc2)
        homo_time = (time.time() - start) / num_operations
        results['Paillier']['homo_op'].append(homo_time)
        print(f"  Homomorphic addition (avg): {homo_time:.6f}s")

        # Test RSA
        print(f"\n[RSA Cryptosystem]")
        start = time.time()
        rsa = RSACryptosystem(key_size=key_size)
        keygen_time = time.time() - start
        results['RSA']['keygen'].append(keygen_time)
        print(f"  Key generation: {keygen_time:.4f}s")

        # Encryption benchmark
        start = time.time()
        for _ in range(num_operations):
            enc = rsa.encrypt(message)
        encrypt_time = (time.time() - start) / num_operations
        results['RSA']['encrypt'].append(encrypt_time)
        print(f"  Encryption (avg): {encrypt_time:.6f}s")

        # Decryption benchmark
        start = time.time()
        for _ in range(num_operations):
            dec = rsa.decrypt(enc)
        decrypt_time = (time.time() - start) / num_operations
        results['RSA']['decrypt'].append(decrypt_time)
        print(f"  Decryption (avg): {decrypt_time:.6f}s")

        # Homomorphic multiplication benchmark
        enc1 = rsa.encrypt(10)
        enc2 = rsa.encrypt(20)
        start = time.time()
        for _ in range(num_operations):
            result = rsa.homomorphic_multiply(enc1, enc2)
        homo_time = (time.time() - start) / num_operations
        results['RSA']['homo_op'].append(homo_time)
        print(f"  Homomorphic multiplication (avg): {homo_time:.6f}s")

        # Test ElGamal
        print(f"\n[ElGamal Cryptosystem]")
        start = time.time()
        elgamal = ElGamalCryptosystem(key_size=key_size)
        keygen_time = time.time() - start
        results['ElGamal']['keygen'].append(keygen_time)
        print(f"  Key generation: {keygen_time:.4f}s")

        # Encryption benchmark
        start = time.time()
        for _ in range(num_operations):
            enc = elgamal.encrypt(message)
        encrypt_time = (time.time() - start) / num_operations
        results['ElGamal']['encrypt'].append(encrypt_time)
        print(f"  Encryption (avg): {encrypt_time:.6f}s")

        # Decryption benchmark
        start = time.time()
        for _ in range(num_operations):
            dec = elgamal.decrypt(enc)
        decrypt_time = (time.time() - start) / num_operations
        results['ElGamal']['decrypt'].append(decrypt_time)
        print(f"  Decryption (avg): {decrypt_time:.6f}s")

        # Homomorphic multiplication benchmark
        enc1 = elgamal.encrypt(10)
        enc2 = elgamal.encrypt(20)
        start = time.time()
        for _ in range(num_operations):
            result = elgamal.homomorphic_multiply(enc1, enc2)
        homo_time = (time.time() - start) / num_operations
        results['ElGamal']['homo_op'].append(homo_time)
        print(f"  Homomorphic multiplication (avg): {homo_time:.6f}s")

    # Print summary comparison
    print(f"\n{'='*80}")
    print("PERFORMANCE SUMMARY")
    print(f"{'='*80}")

    operations = ['keygen', 'encrypt', 'decrypt', 'homo_op']
    op_names = ['Key Generation', 'Encryption', 'Decryption', 'Homomorphic Op']

    for idx, op in enumerate(operations):
        print(f"\n{op_names[idx]}:")
        print(f"  {'Scheme':<15} {'256-bit':<20} {'512-bit':<20}")
        print(f"  {'-'*55}")
        for scheme in ['Paillier', 'RSA', 'ElGamal']:
            times = results[scheme][op]
            if len(times) >= 2:
                print(f"  {scheme:<15} {times[0]:<20.6f} {times[1]:<20.6f}")


def main():
    """Main function to run all tests"""

    try:
        # Lab Exercise 2: RSA Multiplication
        test_rsa_multiplication()

        # Question 1a: ElGamal Multiplication
        test_elgamal_multiplication()

        # Question 1b: Secure Data Sharing
        test_secure_data_sharing()

        # Question 1c: Secure Thresholding
        test_secure_thresholding()

        # Question 1d: Performance Analysis
        test_performance_analysis()


    except Exception as e:
        print(f"\n✗ ERROR: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()