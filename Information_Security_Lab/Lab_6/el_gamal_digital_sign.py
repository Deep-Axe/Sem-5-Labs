import random
import hashlib


def is_prime(n, k=5):
    """Miller-Rabin primality test"""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    r, d = 0, n - 1
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


def generate_prime(bits=256):
    """Generate a prime number"""
    while True:
        num = random.getrandbits(bits)
        num |= (1 << bits - 1) | 1
        if is_prime(num):
            return num


def find_primitive_root(p):
    """Find a primitive root modulo p"""
    if p == 2:
        return 1

    # Find prime factors of p-1
    phi = p - 1
    factors = []
    n = phi

    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            factors.append(i)
            while n % i == 0:
                n //= i
    if n > 1:
        factors.append(n)

    # Test random elements
    for _ in range(100):
        g = random.randint(2, p - 1)
        flag = True
        for factor in factors:
            if pow(g, phi // factor, p) == 1:
                flag = False
                break
        if flag:
            return g

    return 2  # Fallback


def mod_inverse(a, m):
    """Calculate modular multiplicative inverse"""

    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd_val, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd_val, x, y

    gcd_val, x, _ = extended_gcd(a % m, m)
    if gcd_val != 1:
        return None
    return (x % m + m) % m


def generate_elgamal_keys(bits=256):
    """Generate ElGamal keys"""
    print(f"Generating {bits}-bit ElGamal keys...")

    # Generate large prime p
    p = generate_prime(bits)

    # Find primitive root g
    g = find_primitive_root(p)

    # Choose private key x (1 < x < p-1)
    x = random.randint(2, p - 2)

    # Calculate public key y = g^x mod p
    y = pow(g, x, p)

    print("Keys generated successfully!")
    return (p, g, y), (p, g, x)


def hash_message(message):
    """Hash message using SHA-256"""
    return int(hashlib.sha256(message.encode()).hexdigest(), 16)


def sign_message(message, private_key):
    """Sign a message using ElGamal"""
    p, g, x = private_key
    message_hash = hash_message(message) % p

    while True:
        # Choose random k coprime to p-1
        k = random.randint(2, p - 2)
        if mod_inverse(k, p - 1) is not None:
            break

    # Calculate r = g^k mod p
    r = pow(g, k, p)

    # Calculate s = k^(-1) * (H(m) - x*r) mod (p-1)
    k_inv = mod_inverse(k, p - 1)
    s = (k_inv * (message_hash - x * r)) % (p - 1)

    return (r,s)


def verify_signature(message, signature, public_key):
    """Verify an ElGamal signature"""
    p, g, y = public_key
    r, s = signature

    # Check if 0 < r < p and 0 < s < p-1
    if not (0 < r < p and 0 <= s < p - 1):
        return False

    message_hash = hash_message(message) % p

    # Verify: g^H(m) ≡ y^r * r^s (mod p)
    left = pow(g, message_hash, p)
    right = (pow(y, r, p) * pow(r, s, p)) % p

    return left == right


def main():


    while True:
        print("\nOptions:")
        print("1. Generate new ElGamal keys")
        print("2. Sign a message")
        print("3. Verify a signature")
        print("4. Exit")

        choice = input("\nEnter your choice (1-4): ").strip()

        if choice == '1':
            bits = input("Enter key size in bits (default 256): ").strip()
            bits = int(bits) if bits else 256

            public_key, private_key = generate_elgamal_keys(bits)
            p, g, y = public_key
            _, _, x = private_key

            print("\n")
            print("GENERATED KEYS:")

            print(f"Public Key (p, g, y):")
            print(f"  p (Prime): {p}")
            print(f"  g (Generator): {g}")
            print(f"  y (Public Key): {y}")
            print(f"\nPrivate Key (p, g, x):")
            print(f"  p (Prime): {p}")
            print(f"  g (Generator): {g}")
            print(f"  x (Private Key): {x}")


        elif choice == '2':
            print("\nEnter Private Key:")
            p = int(input("  Prime (p): ").strip())
            g = int(input("  Generator (g): ").strip())
            x = int(input("  Private Key (x): ").strip())

            message = input("\nEnter message to sign: ").strip()

            private_key = (p, g, x)
            signature = sign_message(message, private_key)

            print("\n")
            print("DIGITAL SIGNATURE:")

            print(f"Message: {message}")
            print(f"Signature (r, s):")
            print(f"  r: {signature[0]}")
            print(f"  s: {signature[1]}")

        elif choice == '3':
            print("\nEnter Public Key:")
            p = int(input("  Prime (p): ").strip())
            g = int(input("  Generator (g): ").strip())
            y = int(input("  Public Key (y): ").strip())

            message = input("\nEnter original message: ").strip()

            print("\nEnter Signature:")
            r = int(input("  r: ").strip())
            s = int(input("  s: ").strip())

            public_key = (p, g, y)
            signature = (r, s)
            is_valid = verify_signature(message, signature, public_key)

            print("\n")
            print("VERIFICATION RESULT:")

            if is_valid:
                print(" Signature is VALID")
                print(f"Message authenticated: '{message}'")
            else:
                print(" Signature is INVALID")
                print(" Message may have been tampered with!")

        elif choice == '4':
            print("\nExiting...")
            break

        else:
            print("Invalid choice! Please try again.")


if __name__ == "__main__":
    main()
