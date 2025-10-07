import random
import hashlib
def gcd(a, b):
    """Calculate Greatest Common Divisor"""
    while b:
        a, b = b, a % b
    return a


def mod_inverse(e, phi):
    """Calculate modular multiplicative inverse using Extended Euclidean Algorithm"""

    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd_val, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd_val, x, y

    _, x, _ = extended_gcd(e % phi, phi)
    return (x % phi + phi) % phi


def is_prime(n, k=5):
    """Miller-Rabin primality test"""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Witness loop
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


def generate_prime(bits=512):
    """Generate a prime number with specified bit length"""
    while True:
        num = random.getrandbits(bits)
        num |= (1 << bits - 1) | 1  # Set MSB and LSB to 1
        if is_prime(num):
            return num


def generate_rsa_keys(bits=512):
    """Generate RSA public and private keys"""
    print(f"Generating {bits}-bit RSA keys...")

    # Generate two distinct primes
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    while p == q:
        q = generate_prime(bits // 2)

    n = p * q
    phi = (p - 1) * (q - 1)

    # Choose public exponent e
    e = 65537  # Common choice (0x10001)

    # Calculate private exponent d
    d = mod_inverse(e, phi)

    print("Keys generated successfully!")
    return (e, n), (d, n)


def hash_message(message):
    """Hash message using SHA-256"""
    return int(hashlib.sha256(message.encode()).hexdigest(), 16)


def sign_message(message, private_key):
    """Sign a message using RSA private key"""
    d, n = private_key
    message_hash = hash_message(message)

    # Reduce hash to fit within modulus
    message_hash = message_hash % n

    # Sign: signature = hash^d mod n
    signature = pow(message_hash, d, n)
    return signature


def verify_signature(message, signature, public_key):
    """Verify a signature using RSA public key"""
    e, n = public_key
    message_hash = hash_message(message)

    # Reduce hash to fit within modulus
    message_hash = message_hash % n

    # Verify: hash' = signature^e mod n
    decrypted_hash = pow(signature, e, n)

    return decrypted_hash == message_hash


def main():

    while True:
        print("\nOptions:")
        print("1. Generate new RSA keys")
        print("2. Sign a message")
        print("3. Verify a signature")
        print("4. Exit")

        choice = input("\nEnter your choice (1-4): ").strip()

        if choice == '1':
            bits = input("Enter key size in bits (default 512): ").strip()
            bits = int(bits) if bits else 512

            public_key, private_key = generate_rsa_keys(bits)
            e, n = public_key
            d, _ = private_key

            print("\n" + "=" * 60)
            print("GENERATED KEYS:")

            print(f"Public Key (e, n):")
            print(f"  e (Public Exponent): {e}")
            print(f"  n (Public Modulus):  {n}")
            print(f"\nPrivate Key (d, n):")
            print(f"  d (Private Exponent): {d}")
            print(f"  n (Public Modulus):   {n}")


        elif choice == '2':
            print("\nEnter Private Key:")
            d = int(input("  Private Exponent (d): ").strip())
            n = int(input("  Public Modulus (n): ").strip())

            message = input("\nEnter message to sign: ").strip()

            private_key = (d, n)
            signature = sign_message(message, private_key)

            print("\n" )
            print("DIGITAL SIGNATURE:")

            print(f"Message: {message}")
            print(f"Signature: {signature}")


        elif choice == '3':
            print("\nEnter Public Key:")
            e = int(input("  Public Exponent (e): ").strip())
            n = int(input("  Public Modulus (n): ").strip())

            message = input("\nEnter original message: ").strip()
            signature = int(input("Enter signature to verify: ").strip())

            public_key = (e, n)
            is_valid = verify_signature(message, signature, public_key)

            print("\n")
            print("VERIFICATION RESULT:")

            if is_valid:
                print("Signature is VALID")
                print(f" Message authenticated: '{message}'")
            else:
                print("Signature is INVALID")
                print(" Message may have been tampered with!")


        elif choice == '4':
            print("\nExiting...")
            break

        else:
            print("Invalid choice! Please try again.")


if __name__ == "__main__":
    main()