import os
import time
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def save_data(filename, data):
    with open(filename, 'wb') as f:
        f.write(data)


def load_data(filename):
    with open(filename, 'rb') as f:
        return f.read()


def menu():
    print("\n==== Secure File Transfer Menu ====")
    print("1. Generate RSA 2048 Key Pair")
    print("2. Generate ECC secp256r1 Key Pair")
    print("3. Export My Public Key")
    print("4. Import Peer Public Key")
    print("5. Encrypt a File")
    print("6. Decrypt a File")
    print("7. Show Loaded Keys")
    print("8. Exit")
    print("===================================")


# --- Key Operations ---
def generate_rsa_keys():
    start = time.time()
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    elapsed = time.time() - start
    print(f"RSA 2048 key generated in {elapsed:.2f} seconds.")

    # Save private key
    save_data("my_rsa_private.pem", private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

    # Save public key
    save_data("my_rsa_public.pem", private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))
    return private_key


def generate_ecc_keys():
    start = time.time()
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    elapsed = time.time() - start
    print(f"ECC P-256 key generated in {elapsed:.2f} seconds.")

    # Save private key
    save_data("my_ecc_private.pem", private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

    # Save public key
    save_data("my_ecc_public.pem", private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))
    return private_key


def load_rsa_private():
    if os.path.exists("my_rsa_private.pem"):
        return serialization.load_pem_private_key(
            load_data("my_rsa_private.pem"),
            password=None,
            backend=default_backend()
        )
    return None


def load_rsa_public():
    if os.path.exists("my_rsa_public.pem"):
        return serialization.load_pem_public_key(
            load_data("my_rsa_public.pem"),
            backend=default_backend()
        )
    return None


def load_ecc_private():
    if os.path.exists("my_ecc_private.pem"):
        return serialization.load_pem_private_key(
            load_data("my_ecc_private.pem"),
            password=None,
            backend=default_backend()
        )
    return None


def load_ecc_public():
    if os.path.exists("my_ecc_public.pem"):
        return serialization.load_pem_public_key(
            load_data("my_ecc_public.pem"),
            backend=default_backend()
        )
    return None


def export_public_key(keytype):
    if keytype == "RSA":
        pubkey = load_rsa_public()
        if pubkey:
            fname = input("Export as filename: ").strip()
            save_data(fname, pubkey.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
            print("Exported.")
        else:
            print("No RSA public key loaded.")
    elif keytype == "ECC":
        pubkey = load_ecc_public()
        if pubkey:
            fname = input("Export as filename: ").strip()
            save_data(fname, pubkey.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
            print("Exported.")
        else:
            print("No ECC public key loaded.")


def import_peer_public_key():
    algo = input("Peer key type (RSA/ECC): ").strip().upper()
    fname = input("Peer public key filename: ").strip()
    if not os.path.exists(fname):
        print("File does not exist.")
        return None, None

    try:
        key = serialization.load_pem_public_key(
            load_data(fname),
            backend=default_backend()
        )
        if algo == "RSA":
            save_data("peer_rsa_public.pem", load_data(fname))
            print("Loaded and saved as peer_rsa_public.pem")
        elif algo == "ECC":
            save_data("peer_ecc_public.pem", load_data(fname))
            print("Loaded and saved as peer_ecc_public.pem")
        return algo, key
    except Exception as e:
        print(f"Error loading key: {e}")
        return None, None


def load_peer_rsa_public():
    if os.path.exists("peer_rsa_public.pem"):
        return serialization.load_pem_public_key(
            load_data("peer_rsa_public.pem"),
            backend=default_backend()
        )
    return None


def load_peer_ecc_public():
    if os.path.exists("peer_ecc_public.pem"):
        return serialization.load_pem_public_key(
            load_data("peer_ecc_public.pem"),
            backend=default_backend()
        )
    return None


# --- Hybrid Encryption ---
def hybrid_encrypt_file(filename, outfile, algo, peer_key):
    start_time = time.time()
    file_data = load_data(filename)

    # Generate AES key and encrypt file
    aes_key = os.urandom(32)  # 256-bit key
    iv = os.urandom(12)  # GCM nonce

    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(file_data) + encryptor.finalize()
    tag = encryptor.tag

    # Encrypt AES key with public key
    if algo == "RSA":
        enc_key = peer_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        method = b"RSA"
    elif algo == "ECC":
        # Simple ECDH (in practice, use proper key derivation)
        my_priv = load_ecc_private()
        shared_key = my_priv.exchange(ec.ECDH(), peer_key)
        # Derive encryption key from shared secret
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(shared_key)
        derived = digest.finalize()[:32]
        # XOR AES key with derived key (simplified)
        enc_key = bytes(a ^ b for a, b in zip(aes_key, derived))
        method = b"ECC"

    # Save encrypted file
    with open(outfile, 'wb') as f:
        f.write(method)  # 3 bytes
        f.write(len(enc_key).to_bytes(2, 'big'))  # 2 bytes
        f.write(enc_key)  # variable length
        f.write(iv)  # 12 bytes
        f.write(tag)  # 16 bytes
        f.write(ciphertext)  # rest

    elapsed = time.time() - start_time
    print(f"Encrypted {filename} → {outfile} in {elapsed:.3f} seconds")


def hybrid_decrypt_file(filename, outfile):
    start_time = time.time()

    with open(filename, 'rb') as f:
        method = f.read(3)
        keylen = int.from_bytes(f.read(2), 'big')
        enc_key = f.read(keylen)
        iv = f.read(12)
        tag = f.read(16)
        ciphertext = f.read()

    # Decrypt AES key
    if method == b"RSA":
        privkey = load_rsa_private()
        if not privkey:
            print("No RSA private key loaded.")
            return
        aes_key = privkey.decrypt(
            enc_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    elif method == b"ECC":
        my_priv = load_ecc_private()
        peer_pub = load_peer_ecc_public()
        if not (my_priv and peer_pub):
            print("Missing ECC key(s).")
            return
        shared_key = my_priv.exchange(ec.ECDH(), peer_pub)
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(shared_key)
        derived = digest.finalize()[:32]
        aes_key = bytes(a ^ b for a, b in zip(enc_key, derived))
    else:
        print("Unknown encryption method.")
        return

    # Decrypt file
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    try:
        plain = decryptor.update(ciphertext) + decryptor.finalize()
        save_data(outfile, plain)
        elapsed = time.time() - start_time
        print(f"Decrypted {filename} → {outfile} in {elapsed:.3f} seconds")
    except Exception as e:
        print("Decryption failed:", e)


def show_loaded_keys():
    print("\n-- Your Keys --")
    print("RSA private loaded:", "Yes" if load_rsa_private() else "No")
    print("RSA public loaded:", "Yes" if load_rsa_public() else "No")
    print("ECC private loaded:", "Yes" if load_ecc_private() else "No")
    print("ECC public loaded:", "Yes" if load_ecc_public() else "No")
    print("-- Peer Keys --")
    print("Peer RSA public loaded:", "Yes" if load_peer_rsa_public() else "No")
    print("Peer ECC public loaded:", "Yes" if load_peer_ecc_public() else "No")


def main():
    while True:
        menu()
        choice = input("Choice: ").strip()

        if choice == "1":
            generate_rsa_keys()
        elif choice == "2":
            generate_ecc_keys()
        elif choice == "3":
            kt = input("Key type to export (RSA/ECC): ").strip().upper()
            export_public_key(kt)
        elif choice == "4":
            import_peer_public_key()
        elif choice == "5":
            algo = input("Encrypt using (RSA/ECC): ").strip().upper()
            infile = input("File to encrypt: ").strip()
            outfile = input("Output file: ").strip()

            if algo == "RSA":
                peer_key = load_peer_rsa_public()
                if not peer_key:
                    print("Peer RSA public key not loaded.")
                    continue
            elif algo == "ECC":
                peer_key = load_peer_ecc_public()
                if not peer_key or not load_ecc_private():
                    print("Peer ECC public key or your ECC private key not loaded.")
                    continue
            else:
                print("Invalid algorithm.")
                continue

            hybrid_encrypt_file(infile, outfile, algo, peer_key)
        elif choice == "6":
            infile = input("File to decrypt: ").strip()
            outfile = input("Output file: ").strip()
            hybrid_decrypt_file(infile, outfile)
        elif choice == "7":
            show_loaded_keys()
        elif choice == "8":
            print("Bye!")
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()