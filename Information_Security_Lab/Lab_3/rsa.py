import random


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def mod_inverse(e, phi):

    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        return None
    return (x % phi + phi) % phi


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


def generate_prime(bits):
    while True:
        n = random.getrandbits(bits)
        n |= (1 << bits - 1) | 1
        if is_prime(n):
            return n


def generate_rsa_keys():
    print("Generating RSA keys... Please wait...")

    p = generate_prime(1024)
    q = generate_prime(1024)

    while p == q:
        q = generate_prime(1024)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    while gcd(e, phi) != 1:
        e += 2

    d = mod_inverse(e, phi)

    return (n, e), (n, d)


def string_to_blocks(message, block_size):
    message_bytes = message.encode('utf-8')
    blocks = []

    for i in range(0, len(message_bytes), block_size):
        block = message_bytes[i:i + block_size]
        block_int = int.from_bytes(block, byteorder='big')
        blocks.append(block_int)

    return blocks


def blocks_to_string(blocks):
    message_bytes = b''

    for block_int in blocks:
        byte_length = (block_int.bit_length() + 7) // 8
        if byte_length == 0:
            byte_length = 1
        block_bytes = block_int.to_bytes(byte_length, byteorder='big')
        message_bytes += block_bytes

    return message_bytes.decode('utf-8', errors='ignore')


def encrypt_rsa(message, public_key):
    try:
        n, e = public_key

        max_block_size = (n.bit_length() - 1) // 8 - 1
        blocks = string_to_blocks(message, max_block_size)

        encrypted_blocks = []
        for block in blocks:
            if block >= n:
                return "Error: Message block too large for key size"
            encrypted_block = pow(block, e, n)
            encrypted_blocks.append(encrypted_block)

        ciphertext_str = ','.join([str(block) for block in encrypted_blocks])
        return ciphertext_str

    except Exception as e:
        return f"Encryption failed: {str(e)}"


def decrypt_rsa(ciphertext_str, private_key):
    try:
        n, d = private_key

        encrypted_blocks = [int(block.strip()) for block in ciphertext_str.split(',')]

        decrypted_blocks = []
        for encrypted_block in encrypted_blocks:
            decrypted_block = pow(encrypted_block, d, n)
            decrypted_blocks.append(decrypted_block)

        decrypted_message = blocks_to_string(decrypted_blocks)
        return decrypted_message

    except Exception as e:
        return f"Decryption failed: {str(e)}"


def main():
    print("RSA Encryption/Decryption System")
    result = ''

    public_key = None
    private_key = None

    while True:
        choice = input("Enter generate, encrypt or decrypt using RSA cipher or exit out of prg: ")

        if choice == "generate":
            print("Generating RSA key pair (2048-bit)...")
            public_key, private_key = generate_rsa_keys()
            print("RSA keys generated successfully!")
            print(f"Public key (n, e): ({public_key[0]}, {public_key[1]})")
            print(f"Private key (n, d): ({private_key[0]}, {private_key[1]})")

        elif choice == "encrypt":
            if not public_key:
                print("No keys available. Please generate keys first.")
                continue

            message = input("Enter plain text: ")
            result = encrypt_rsa(message, public_key)
            print("Public key used:", f"({public_key[0]}, {public_key[1]})")

        elif choice == "decrypt":
            if not private_key:
                print("No keys available. Please generate keys first.")
                continue

            ciphertext_str = input("Enter ciphertext (comma-separated numbers): ")
            result = decrypt_rsa(ciphertext_str, private_key)
            print("Private key used:", f"({private_key[0]}, {private_key[1]})")

        elif choice == "exit":
            break

        else:
            print("Invalid choice")
            continue

        if choice in ["encrypt", "decrypt"]:
            print("Resultant encryption/decryption is:", result)
        print()


if __name__ == '__main__':
    main()