import random

# Given ElGamal parameters
p = 7919
g = 2
h = 6465
x = 2999  # Private key

# Step 1: Convert message to integer
message = "Asymmetric Algorithms"
m_int = int.from_bytes(message.encode('utf-8'), 'big')

if m_int >= p:
    raise ValueError("Message too large for given modulus p. Use a larger p or split the message.")

# Step 2: Random ephemeral key
k = random.randint(1, p - 2)

# Step 3: Encryption
c1 = pow(g, k, p)
c2 = (m_int * pow(h, k, p)) % p

print(f"Ciphertext (c1, c2): ({c1}, {c2})")

# Step 4: Decryption
# Compute modular inverse of (c1^x mod p)
s = pow(c1, x, p)
s_inv = pow(s, -1, p)
m_decrypted_int = (c2 * s_inv) % p

# Step 5: Convert back to string
decrypted_message = m_decrypted_int.to_bytes((m_decrypted_int.bit_length() + 7) // 8, 'big').decode('utf-8')

print("Decrypted message:", decrypted_message)
