from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# Step 1: Generate ECC private and public keys (secp256r1 curve)
private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()

# Step 2: Simulate a sender generating an ephemeral ECC key for encryption
sender_private_key = ec.generate_private_key(ec.SECP256R1())
sender_public_key = sender_private_key.public_key()

# Step 3: Derive a shared secret using ECDH
shared_secret = sender_private_key.exchange(ec.ECDH(), public_key)

# Step 4: Derive a symmetric key from the shared secret using HKDF
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"ECC Encryption Example",
).derive(shared_secret)

# Step 5: Encrypt the message using AES-GCM
message = b"Secure Transactions"
aesgcm = AESGCM(derived_key)
nonce = os.urandom(12)
ciphertext = aesgcm.encrypt(nonce, message, None)

print("Ciphertext:", ciphertext.hex())

# Step 6: Decrypt the ciphertext using the recipient’s private key
# (Receiver derives the same shared key using their private key and sender's public key)
receiver_shared_secret = private_key.exchange(ec.ECDH(), sender_public_key)
receiver_derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"ECC Encryption Example",
).derive(receiver_shared_secret)

aesgcm_receiver = AESGCM(receiver_derived_key)
decrypted_message = aesgcm_receiver.decrypt(nonce, ciphertext, None)

print("Decrypted message:", decrypted_message.decode())
