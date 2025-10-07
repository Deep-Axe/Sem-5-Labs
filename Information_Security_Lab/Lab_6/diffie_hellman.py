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

    phi = p - 1
    factors = []
    n = phi

    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            factors.append(i)
            while n % i == 0:
                n //= i
    if n > 1:
        factors.append(n)

    for _ in range(100):
        g = random.randint(2, p - 1)
        flag = True
        for factor in factors:
            if pow(g, phi // factor, p) == 1:
                flag = False
                break
        if flag:
            return g

    return 2


def generate_dh_parameters(bits=256):
    """Generate Diffie-Hellman parameters"""
    print(f"Generating {bits}-bit Diffie-Hellman parameters...")
    p = generate_prime(bits)
    g = find_primitive_root(p)
    print("Parameters generated successfully!")
    return p, g


def generate_dh_keypair(p, g):
    """Generate DH private and public key"""
    private_key = random.randint(2, p - 2)
    public_key = pow(g, private_key, p)
    return private_key, public_key


def compute_shared_secret(other_public_key, my_private_key, p):
    """Compute shared secret"""
    return pow(other_public_key, my_private_key, p)


def hash_value(*args):
    """Hash values using SHA-256"""
    hasher = hashlib.sha256()
    for arg in args:
        hasher.update(str(arg).encode())
    return hasher.hexdigest()


def sign_dh_public_key(dh_public_key, identity, signing_key):
    """
    Sign DH public key with identity
    Simple signature: H(identity || dh_public_key || signing_key)
    """
    signature = hash_value(identity, dh_public_key, signing_key)
    return signature


def verify_dh_signature(dh_public_key, identity, signature, signing_key):
    """Verify DH public key signature"""
    expected_signature = hash_value(identity, dh_public_key, signing_key)
    return signature == expected_signature


def main():

    print("DIFFIE-HELLMAN AUTHENTICATED KEY EXCHANGE")

    print("\nNote: This demonstrates DH key exchange with authentication")
    print("using digital signatures to prevent man-in-the-middle attacks.")

    params = None
    alice_keys = None
    bob_keys = None

    while True:
        print("\n")
        print("Options:")
        print("1. Generate DH parameters (p, g)")
        print("2. Generate Alice's keys")
        print("3. Generate Bob's keys")
        print("4. Perform authenticated key exchange")
        print("5. Manual key exchange")
        print("6. Exit")

        choice = input("\nEnter your choice (1-6): ").strip()

        if choice == '1':
            bits = input("Enter parameter size in bits (default 256): ").strip()
            bits = int(bits) if bits else 256

            p, g = generate_dh_parameters(bits)
            params = (p, g)

            print("\n" + "=" * 70)
            print("DIFFIE-HELLMAN PARAMETERS:")
            print("=" * 70)
            print(f"p (Prime Modulus): {p}")
            print(f"g (Generator): {g}")
            print("=" * 70)

        elif choice == '2':
            if params is None:
                print("\nPlease generate DH parameters first (Option 1)!")
                continue

            p, g = params

            # Generate DH keys for Alice
            alice_private, alice_public = generate_dh_keypair(p, g)

            # Generate signing key for Alice
            alice_signing_key = random.getrandbits(128)

            # Sign Alice's public key
            alice_signature = sign_dh_public_key(alice_public, "Alice", alice_signing_key)

            alice_keys = {
                'private': alice_private,
                'public': alice_public,
                'signing_key': alice_signing_key,
                'signature': alice_signature,
                'identity': "Alice"
            }

            print("\n" + "=" * 70)
            print("ALICE'S KEYS:")
            print("=" * 70)
            print(f"Identity: Alice")
            print(f"Private Key: {alice_private}")
            print(f"Public Key: {alice_public}")
            print(f"Signing Key: {alice_signing_key}")
            print(f"Signature: {alice_signature}")
            print("=" * 70)

        elif choice == '3':
            if params is None:
                print("\nPlease generate DH parameters first (Option 1)!")
                continue

            p, g = params

            # Generate DH keys for Bob
            bob_private, bob_public = generate_dh_keypair(p, g)

            # Generate signing key for Bob
            bob_signing_key = random.getrandbits(128)

            # Sign Bob's public key
            bob_signature = sign_dh_public_key(bob_public, "Bob", bob_signing_key)

            bob_keys = {
                'private': bob_private,
                'public': bob_public,
                'signing_key': bob_signing_key,
                'signature': bob_signature,
                'identity': "Bob"
            }


            print("BOB'S KEYS:")

            print(f"Identity: Bob")
            print(f"Private Key: {bob_private}")
            print(f"Public Key: {bob_public}")
            print(f"Signing Key: {bob_signing_key}")
            print(f"Signature: {bob_signature}")


        elif choice == '4':
            if params is None or alice_keys is None or bob_keys is None:
                print("\nPlease generate parameters and both keys first!")
                continue

            p, g = params


            print("AUTHENTICATED KEY EXCHANGE:")


            # Alice verifies Bob's signature
            print("\n1. Alice verifies Bob's signature...")
            bob_verified = verify_dh_signature(
                bob_keys['public'],
                bob_keys['identity'],
                bob_keys['signature'],
                bob_keys['signing_key']
            )

            if bob_verified:
                print("   Bob's signature verified!")
            else:
                print("    Bob's signature verification failed!")
                continue

            # Bob verifies Alice's signature
            print("\n2. Bob verifies Alice's signature...")
            alice_verified = verify_dh_signature(
                alice_keys['public'],
                alice_keys['identity'],
                alice_keys['signature'],
                alice_keys['signing_key']
            )

            if alice_verified:
                print("   ✓ Alice's signature verified!")
            else:
                print("   ✗ Alice's signature verification failed!")
                continue

            # Compute shared secrets
            print("\n3. Computing shared secrets...")
            alice_shared = compute_shared_secret(bob_keys['public'], alice_keys['private'], p)
            bob_shared = compute_shared_secret(alice_keys['public'], bob_keys['private'], p)

            print(f"\n   Alice's computed shared secret: {alice_shared}")
            print(f"   Bob's computed shared secret:   {bob_shared}")

            if alice_shared == bob_shared:
                print("\n   ✓ Shared secrets match!")
                print(f"\n   Shared Secret: {alice_shared}")
                print(f"   Session Key (SHA-256): {hash_value(alice_shared)}")
            else:
                print("\n   ✗ Shared secrets don't match!")



        elif choice == '5':
            print("\n")
            print("MANUAL KEY EXCHANGE:")


            print("\nEnter DH Parameters:")
            p = int(input("  p (Prime): ").strip())
            g = int(input("  g (Generator): ").strip())

            print("\nEnter Your Information:")
            my_identity = input("  Your identity: ").strip()
            my_private = int(input("  Your private key: ").strip())
            my_signing_key = int(input("  Your signing key: ").strip())

            # Calculate public key
            my_public = pow(g, my_private, p)
            my_signature = sign_dh_public_key(my_public, my_identity, my_signing_key)

            print(f"\n  Your public key: {my_public}")
            print(f"  Your signature: {my_signature}")

            print("\nEnter Other Party's Information:")
            other_identity = input(" Their identity: ").strip()
            other_public = int(input("  Their public key: ").strip())
            other_signature = input("  Their signature: ").strip()
            other_signing_key = int(input("  Their signing key: ").strip())

            # Verify signature
            print("\nVerifying signature...")
            verified = verify_dh_signature(
                other_public,
                other_identity,
                other_signature,
                other_signing_key
            )

            if verified:
                print("✓ Signature verified!")

                # Compute shared secret
                shared_secret = compute_shared_secret(other_public, my_private, p)
                print(f"\nShared Secret: {shared_secret}")
                print(f"Session Key (SHA-256): {hash_value(shared_secret)}")
            else:
                print("✗ Signature verification failed!")


        elif choice == '6':
            print("\nExiting...")
            break

        else:
            print("Invalid choice! Please try again.")


if __name__ == "__main__":
    main()