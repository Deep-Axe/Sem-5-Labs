import random
import math
from typing import Any

from sympy import isprime


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
            if isprime(num):
                return num

    @staticmethod
    def _lcm(a, b):
        """Calculate the least common multiple"""
        return abs(a * b) // math.gcd(a, b)

    @staticmethod
    def _L(x: int, n: int) -> int | Any:
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


def main():

    # Initialize Paillier cryptosystem
    print("\n Paillier key pair...")
    paillier = PaillierCryptosystem(key_size=512)
    print("Key pair generated successfully!")
    print(f"Public key (n): {paillier.public_key[0]}")
    print(f"Public key (g): {paillier.public_key[1]}")

    # Define two integers to encrypt
    a = 15
    b = 25
    expected_sum = a + b

    print(f"\n[Step 2] Encrypting integers...")
    print(f"Original integer a: {a}")
    print(f"Original integer b: {b}")
    print(f"Expected sum (a + b): {expected_sum}")

    # Encrypt the integers
    ciphertext_a = paillier.encrypt(a)
    ciphertext_b = paillier.encrypt(b)

    print(f"\n[Step 3] Ciphertexts:")
    print(f"Ciphertext of a (15): {ciphertext_a}")
    print(f"Ciphertext of b (25): {ciphertext_b}")

    # Perform homomorphic addition
    print(f"\n[Step 4] Performing homomorphic addition...")
    ciphertext_sum = paillier.homomorphic_add(ciphertext_a, ciphertext_b)
    print(f"Ciphertext of (a + b): {ciphertext_sum}")

    # Decrypt the result
    print(f"\n[Step 5] Decrypting the sum...")
    decrypted_sum = paillier.decrypt(ciphertext_sum)
    print(f"Decrypted sum: {decrypted_sum}")

    # Verify the result
    print(f"\n[Step 6] Verification:")
    print(f"Original sum: {expected_sum}")
    print(f"Decrypted sum: {decrypted_sum}")

    if decrypted_sum == expected_sum:
        print("SUCCESS: Homomorphic addition verified correctly!")
    else:
        print(" ERROR: Verification failed!")

    print("Multiple Encryptions")

    # Demonstrate that different encryptions of the same value produce different ciphertexts
    print(f"\nEncrypting the value {a} three times:")
    enc1 = paillier.encrypt(a)
    enc2 = paillier.encrypt(a)
    enc3 = paillier.encrypt(a)

    print(f"Encryption 1: {enc1}")
    print(f"Encryption 2: {enc2}")
    print(f"Encryption 3: {enc3}")
    print("\nNote: Different ciphertexts due to random 'r' value")

    # But they all decrypt to the same value
    print(f"\nDecryption 1: {paillier.decrypt(enc1)}")
    print(f"Decryption 2: {paillier.decrypt(enc2)}")
    print(f"Decryption 3: {paillier.decrypt(enc3)}")


    print("Multiple Homomorphic Additions")


    c = 30
    ciphertext_c = paillier.encrypt(c)

    print(f"\nAdding three encrypted values: {a} + {b} + {c}")
    result_abc = paillier.homomorphic_add(ciphertext_sum, ciphertext_c)
    decrypted_abc = paillier.decrypt(result_abc)

    print(f"Expected result: {a + b + c}")
    print(f"Decrypted result: {decrypted_abc}")
    print(f"Verification: {decrypted_abc == a + b + c}")


if __name__ == "__main__":
    main()