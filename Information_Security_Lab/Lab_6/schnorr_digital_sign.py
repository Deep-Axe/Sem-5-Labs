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


def find_generator(p, q):
    """Find a generator g of order q in Z*p"""
    h = 2
    while h < p:
        g = pow(h, (p - 1) // q, p)
        if g > 1:
            return g
        h += 1
    return None


def generate_schnorr_parameters(p_bits=512, q_bits=160):
    """Generate Schnorr parameters (p, q, g)"""
    print(f"Generating Schnorr parameters (p:{p_bits}-bit, q:{q_bits}-bit)...")

    # Generate q (prime divisor)
    q = generate_prime(q_bits)

    # Generate p such that p = kq + 1 for some k
    while True:
        k = random.getrandbits(p_bits - q_bits)
        p = k * q + 1
        if p.bit_length() == p_bits and is_prime(p):
            break

    # Find generator g of order q
    g = find_generator(p, q)

    print("Parameters generated successfully!")
    return p, q, g


def generate_schnorr_keys(p, q, g):
    """Generate Schnorr keys"""
    print("Generating Schnorr keys...")

    # Private key: random x (0 < x < q)
    x = random.randint(1, q - 1)

    # Public key: y = g^x mod p
    y = pow(g, x, p)

    print("Keys generated successfully!")
    return (p, q, g, y), (p, q, g, x)


def hash_values(*args):
    """Hash multiple values using SHA-256"""
    hasher = hashlib.sha256()
    for arg in args:
        hasher.update(str(arg).encode())
    return int(hasher.hexdigest(), 16)


def sign_message(message, private_key):
    """Sign a message using Schnorr signature scheme"""
    p, q, g, x = private_key

    # Choose random k (0 < k < q)
    k = random.randint(1, q - 1)

    # Calculate r = g^k mod p
    r = pow(g, k, p)

    # Calculate e = H(M || r) mod q
    e = hash_values(message, r) % q

    # Calculate s = (k - xe) mod q
    s = (k - x * e) % q

    return (e, s)


def verify_signature(message, signature, public_key):
    """Verify a Schnorr signature"""
    p, q, g, y = public_key
    e, s = signature

    # Check if 0 < e < q and 0 < s < q
    if not (0 < e < q and 0 < s < q):
        return False

    # Calculate r_v = g^s * y^e mod p
    r_v = (pow(g, s, p) * pow(y, e, p)) % p

    # Calculate e_v = H(M || r_v) mod q
    e_v = hash_values(message, r_v) % q

    # Verify e == e_v
    return e == e_v


def main():

    params = None

    while True:
        print("\nOptions:")
        print("1. Generate Schnorr parameters (p, q, g)")
        print("2. Generate Schnorr keys")
        print("3. Sign a message")
        print("4. Verify a signature")
        print("5. Exit")

        choice = input("\nEnter your choice (1-5): ").strip()

        if choice == '1':
            p_bits = input("Enter p size in bits (default 512): ").strip()
            p_bits = int(p_bits) if p_bits else 512
            q_bits = input("Enter q size in bits (default 160): ").strip()
            q_bits = int(q_bits) if q_bits else 160

            p, q, g = generate_schnorr_parameters(p_bits, q_bits)
            params = (p, q, g)

            print("\n" + "=" * 60)
            print("SCHNORR PARAMETERS:")

            print(f"p (Large Prime): {p}")
            print(f"q (Prime Divisor): {q}")
            print(f"g (Generator): {g}")


        elif choice == '2':
            if params is None:
                print("\nPlease generate parameters first (Option 1)!")
                continue

            p, q, g = params
            public_key, private_key = generate_schnorr_keys(p, q, g)
            _, _, _, y = public_key
            _, _, _, x = private_key

            print("\n" + "=" * 60)
            print("GENERATED KEYS:")

            print(f"Public Key (p, q, g, y):")
            print(f"  p: {p}")
            print(f"  q: {q}")
            print(f"  g: {g}")
            print(f"  y: {y}")
            print(f"\nPrivate Key (p, q, g, x):")
            print(f"  p: {p}")
            print(f"  q: {q}")
            print(f"  g: {g}")
            print(f"  x: {x}")


        elif choice == '3':
            print("\nEnter Private Key:")
            p = int(input("  p: ").strip())
            q = int(input("  q: ").strip())
            g = int(input("  g: ").strip())
            x = int(input("  x (Private Key): ").strip())

            message = input("\nEnter message to sign: ").strip()

            private_key = (p, q, g, x)
            signature = sign_message(message, private_key)

            print("DIGITAL SIGNATURE:")
            print("=" * 60)
            print(f"Message: {message}")
            print(f"Signature (e, s):")
            print(f"  e: {signature[0]}")
            print(f"  s: {signature[1]}")

        elif choice == '4':
            print("\nEnter Public Key:")
            p = int(input("  p: ").strip())
            q = int(input("  q: ").strip())
            g = int(input("  g: ").strip())
            y = int(input("  y (Public Key): ").strip())

            message = input("\nEnter original message: ").strip()

            print("\nEnter Signature:")
            e = int(input("  e: ").strip())
            s = int(input("  s: ").strip())

            public_key = (p, q, g, y)
            signature = (e, s)
            is_valid = verify_signature(message, signature, public_key)

            print("VERIFICATION RESULT:")

            if is_valid:
                print("Signature is VALID")
                print(f" Message authenticated: '{message}'")
            else:
                print("Signature is INVALID")
                print(" Message may have been tampered with!")


        elif choice == '5':
            print("\nExiting...")
            break

        else:
            print("Invalid choice! Please try again.")


if __name__ == "__main__":
    main()