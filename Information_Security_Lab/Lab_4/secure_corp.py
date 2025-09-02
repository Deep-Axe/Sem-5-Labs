import sys
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

class KeyManagementSystem:
    def __init__(self):
        self.rsa_keys = {}
        self.revoked = set()
        self.dh_params = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
        self.dh_keys = {}

    def generate_rsa_keypair(self, subsystem_name):
        priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub_key = priv_key.public_key()
        self.rsa_keys[subsystem_name] = (priv_key, pub_key)

    def get_rsa_public_key(self, subsystem_name):
        return self.rsa_keys[subsystem_name][1] if subsystem_name in self.rsa_keys else None

    def get_rsa_private_key(self, subsystem_name):
        return self.rsa_keys[subsystem_name][0] if subsystem_name in self.rsa_keys else None

    def revoke_key(self, subsystem_name):
        self.revoked.add(subsystem_name)

    def is_revoked(self, subsystem_name):
        return subsystem_name in self.revoked

    def generate_dh_keypair(self, subsystem_name):
        priv_key = self.dh_params.generate_private_key()
        pub_key = priv_key.public_key()
        self.dh_keys[subsystem_name] = (priv_key, pub_key)

    def get_dh_public_key(self, subsystem_name):
        return self.dh_keys[subsystem_name][1] if subsystem_name in self.dh_keys else None

    def get_dh_private_key(self, subsystem_name):
        return self.dh_keys[subsystem_name][0] if subsystem_name in self.dh_keys else None

class Subsystem:
    def __init__(self, name, kms: KeyManagementSystem):
        self.name = name
        self.kms = kms
        self.kms.generate_rsa_keypair(name)
        self.kms.generate_dh_keypair(name)

    def get_shared_key(self, other_subsystem):
        my_private_key = self.kms.get_dh_private_key(self.name)
        other_public_key = self.kms.get_dh_public_key(other_subsystem)
        shared_key = my_private_key.exchange(other_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'secure-shared-key',
        ).derive(shared_key)
        return derived_key

    def send_secure_message(self, to_subsystem, message):
        if self.kms.is_revoked(self.name) or self.kms.is_revoked(to_subsystem):
            raise Exception("One of the subsystems has revoked keys.")
        recipient_pubkey = self.kms.get_rsa_public_key(to_subsystem)
        ciphertext = recipient_pubkey.encrypt(
            message.encode(),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        signer_privkey = self.kms.get_rsa_private_key(self.name)
        signature = signer_privkey.sign(
            ciphertext,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return ciphertext, signature

    def receive_secure_message(self, from_subsystem, ciphertext, signature):
        if self.kms.is_revoked(self.name) or self.kms.is_revoked(from_subsystem):
            raise Exception("One of the subsystems has revoked keys.")
        sender_pubkey = self.kms.get_rsa_public_key(from_subsystem)
        try:
            sender_pubkey.verify(
                signature,
                ciphertext,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
        except Exception as e:
            raise Exception("Signature verification failed!") from e
        receiver_privkey = self.kms.get_rsa_private_key(self.name)
        plaintext = receiver_privkey.decrypt(
            ciphertext,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        return plaintext.decode()

    def sign_document(self, document_bytes):
        priv_key = self.kms.get_rsa_private_key(self.name)
        signature = priv_key.sign(
            document_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return signature

    def verify_document(self, document_bytes, signature, signer_subsystem):
        pub_key = self.kms.get_rsa_public_key(signer_subsystem)
        try:
            pub_key.verify(
                signature,
                document_bytes,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

def main():
    kms = KeyManagementSystem()
    subsystems = {}

    def add_subsystem():
        name = input("Enter new subsystem name: ").strip()
        if name in subsystems:
            print("Subsystem already exists.")
            return
        subsystems[name] = Subsystem(name, kms)
        print(f"Subsystem '{name}' added.")

    def list_subsystems():
        if not subsystems:
            print("No subsystems available.")
        else:
            for name in subsystems:
                revoked = "(REVOKED)" if kms.is_revoked(name) else ""
                print(f"- {name} {revoked}")

    def send_message():
        sender = input("Sender subsystem: ").strip()
        receiver = input("Receiver subsystem: ").strip()
        if sender not in subsystems or receiver not in subsystems:
            print("Invalid subsystem name(s).")
            return
        message = input("Message to send: ")
        try:
            ciphertext, signature = subsystems[sender].send_secure_message(receiver, message)
            print("\n--- Message Sent ---")
            print(f"Ciphertext (hex): {ciphertext.hex()}")
            print(f"Signature (hex): {signature.hex()}")
            print("--------------------")
        except Exception as e:
            print("Error:", e)

    def receive_message():
        receiver = input("Receiver subsystem: ").strip()
        sender = input("Sender subsystem: ").strip()
        if sender not in subsystems or receiver not in subsystems:
            print("Invalid subsystem name(s).")
            return
        ciphertext_hex = input("Paste ciphertext (hex): ").strip()
        signature_hex = input("Paste signature (hex): ").strip()
        try:
            ciphertext = bytes.fromhex(ciphertext_hex)
            signature = bytes.fromhex(signature_hex)
            plaintext = subsystems[receiver].receive_secure_message(sender, ciphertext, signature)
            print(f"\n[Decrypted Message]: {plaintext}")
        except Exception as e:
            print("Error:", e)

    def sign_doc():
        signer = input("Signer subsystem: ").strip()
        if signer not in subsystems:
            print("Invalid subsystem name.")
            return
        document = input("Document text to sign: ").encode()
        signature = subsystems[signer].sign_document(document)
        print(f"Signature (hex): {signature.hex()}")

    def verify_doc():
        signer = input("Signer subsystem: ").strip()
        verifier = input("Verifier subsystem: ").strip()
        if signer not in subsystems or verifier not in subsystems:
            print("Invalid subsystem name(s).")
            return
        document = input("Document text: ").encode()
        signature_hex = input("Paste signature (hex): ").strip()
        signature = bytes.fromhex(signature_hex)
        is_valid = subsystems[verifier].verify_document(document, signature, signer)
        if is_valid:
            print("Signature is VALID.")
        else:
            print("Signature is INVALID.")

    def revoke():
        name = input("Subsystem to revoke: ").strip()
        if name not in subsystems:
            print("Invalid subsystem name.")
            return
        kms.revoke_key(name)
        print(f"Keys revoked for '{name}'.")

    menu = """
SecureCorp Interactive Secure Communication System

1. Add subsystem
2. List subsystems
3. Send secure message
4. Receive secure message
5. Sign document
6. Verify document
7. Revoke subsystem keys
8. Exit

Choose an option (1-8): """

    # Add some default subsystems
    for name in ["Finance", "HR", "SupplyChain"]:
        subsystems[name] = Subsystem(name, kms)

    while True:
        try:
            choice = input(menu).strip()
            if choice == "1":
                add_subsystem()
            elif choice == "2":
                list_subsystems()
            elif choice == "3":
                send_message()
            elif choice == "4":
                receive_message()
            elif choice == "5":
                sign_doc()
            elif choice == "6":
                verify_doc()
            elif choice == "7":
                revoke()
            elif choice == "8":
                print("Exiting.")
                break
            else:
                print("Invalid option.")
        except KeyboardInterrupt:
            print("\nExiting.")
            break

if __name__ == "__main__":
    main()
