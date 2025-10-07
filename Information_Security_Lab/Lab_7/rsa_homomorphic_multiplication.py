import random
import math
from sympy import isprime


class RSACryptosystem:
    """Implementation of RSA Cryptosystem for Homomorphic Multiplication"""

    def __init__(self, key_size=512):
        """Initialize and generate keys for RSA encryption"""
        self.public_key, self.private_key = self.generate_keypair(key_size)

    def generate_keypair(self, key_size):
        """
        Generates a public/private key pair for RSA encryption

        Returns:
            public_key: (n, e) where n = p*q and e is public exponent
            private_key: (n, d) where d is private exponent
        """
        # Generate two large prime numbers p and q
        p = self._generate_prime(key_size // 2)
        q = self._generate_prime(key_size // 2)

        # Ensure p and q are different
        while p == q:
            q = self._generate_prime(key_size // 2)

        # Calculate n = p * q
        n = p * q

        # Calculate phi(n) = (p-1) * (q-1)
        phi_n = (p - 1) * (q - 1)

        # Choose e such that 1 < e < phi(n) and gcd(e, phi(n)) = 1
        # Common choice is 65537
        e = 65537
        while math.gcd(e, phi_n) != 1:
            e = random.randrange(2, phi_n)

        # Calculate d = e^-1 mod phi(n)
        d = self._mod_inverse(e, phi_n)

        public_key = (n, e)
        private_key = (n, d)

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
    def _mod_inverse(a, n):
        """Calculate modular multiplicative inverse using extended Euclidean algorithm"""
        return pow(a, -1, n)

    def encrypt(self, message):
        """
        Encrypts a message using the public key

        Args:
            message: Integer to encrypt (must be < n)

        Returns:
            ciphertext: Encrypted message
        """
        n, e = self.public_key

        # Ensure message is less than n
        if message >= n:
            raise ValueError(f"Message must be less than n ({n})")

        # Calculate ciphertext: c = m^e mod n
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

        # Calculate m = c^d mod n
        message = pow(ciphertext, d, n)

        return message

    def homomorphic_multiply(self, ciphertext1, ciphertext2):
        """
        Performs homomorphic multiplication on two ciphertexts

        RSA Property: E(m1) * E(m2) mod n = E(m1 * m2 mod n)

        Args:
            ciphertext1: First encrypted message
            ciphertext2: Second encrypted message

        Returns:
            result: Encrypted product of the two messages
        """
        n, e = self.public_key

        # Homomorphic multiplication: E(m1 * m2) = E(m1) * E(m2) mod n
        result = (ciphertext1 * ciphertext2) % n

        return result


def main():

    print("RSA HOMOMORPHIC MULTIPLICATION")


    # Initialize RSA cryptosystem
    print("\n[Step 1] Generating RSA key pair...")
    rsa = RSACryptosystem(key_size=512)
    print("Key pair generated successfully!")
    print(f"Public key (n): {rsa.public_key[0]}")
    print(f"Public key (e): {rsa.public_key[1]}")
    print(f"Private key (d): {rsa.private_key[1]}")

    # Define two integers to encrypt
    a = 7
    b = 3
    expected_product = a * b

    print(f"\n[Step 2] Encrypting integers...")
    print(f"Original integer a: {a}")
    print(f"Original integer b: {b}")
    print(f"Expected product (a * b): {expected_product}")

    # Encrypt the integers
    ciphertext_a = rsa.encrypt(a)
    ciphertext_b = rsa.encrypt(b)

    print(f"\n[Step 3] Ciphertexts:")
    print(f"Ciphertext of a (7): {ciphertext_a}")
    print(f"Ciphertext of b (3): {ciphertext_b}")

    # Perform homomorphic multiplication
    print(f"\n[Step 4] Performing homomorphic multiplication...")
    ciphertext_product = rsa.homomorphic_multiply(ciphertext_a, ciphertext_b)
    print(f"Ciphertext of (a * b): {ciphertext_product}")

    # Decrypt the result
    print(f"\n[Step 5] Decrypting the product...")
    decrypted_product = rsa.decrypt(ciphertext_product)
    print(f"Decrypted product: {decrypted_product}")

    # Verify the result
    print(f"\n[Step 6] Verification:")
    print(f"Original product: {expected_product}")
    print(f"Decrypted product: {decrypted_product}")

    if decrypted_product == expected_product:
        print("SUCCESS: Homomorphic multiplication verified correctly!")
    else:
        print("ERROR: Verification failed!")

    print("Multiple Homomorphic Multiplications")


    c = 5
    ciphertext_c = rsa.encrypt(c)

    print(f"\nMultiplying three encrypted values: {a} * {b} * {c}")
    result_abc = rsa.homomorphic_multiply(ciphertext_product, ciphertext_c)
    decrypted_abc = rsa.decrypt(result_abc)

    print(f"Expected result: {a * b * c}")
    print(f"Decrypted result: {decrypted_abc}")
    print(f" Verification: {decrypted_abc == a * b * c}")

    print("\nRSA Homomorphic Property:")
    print("E(m1) * E(m2) mod n = E(m1 * m2 mod n)")


    # Verify with manual calculation
    m1, m2 = 4, 6
    c1 = rsa.encrypt(m1)
    c2 = rsa.encrypt(m2)
    c_product = rsa.homomorphic_multiply(c1, c2)

    print(f"\nTest: {m1} * {m2} = {m1 * m2}")
    print(f"Decrypted result: {rsa.decrypt(c_product)}")
    print(f"Match: {rsa.decrypt(c_product) == m1 * m2}")


if __name__ == "__main__":
    main()
