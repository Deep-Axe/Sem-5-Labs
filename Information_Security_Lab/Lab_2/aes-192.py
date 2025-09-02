from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from binascii import hexlify

# Message and key
message = b"Top Secret Data"  # 16 bytes
key_hex = "FEDCBA9876543210FEDCBA9876543210"
key = bytes.fromhex(key_hex)

# Pad message if necessary (AES block size = 16)
padded_message = pad(message, AES.block_size)

# Create AES cipher (AES-192)
cipher = AES.new(key, AES.MODE_ECB)

# Encrypt
ciphertext = cipher.encrypt(padded_message)

print("Plaintext:", message)
print("Key (hex):", key_hex)
print("Ciphertext (hex):", hexlify(ciphertext).decode())
