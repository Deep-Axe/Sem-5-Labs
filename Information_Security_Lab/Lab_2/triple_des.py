import binascii
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad


def encrypt_3des(message, key):
    try:
        if len(key) < 24:
            key = key.ljust(24, '0')
        elif len(key) > 24:
            key = key[:24]

        key_bytes = key.encode('utf-8')
        message_bytes = message.encode('utf-8')
        cipher = DES3.new(key_bytes, DES3.MODE_ECB)
        padded_message = pad(message_bytes, DES3.block_size)
        ciphertext = cipher.encrypt(padded_message)
        ciphertext_hex = binascii.hexlify(ciphertext).decode('utf-8').upper()

        return ciphertext_hex

    except Exception as e:
        return f"Encryption failed: {str(e)}"


def decrypt_3des(ciphertext_hex, key):
    try:
        if len(key) < 24:
            key = key.ljust(24, '0')
        elif len(key) > 24:
            key = key[:24]

        key_bytes = key.encode('utf-8')
        ciphertext = binascii.unhexlify(ciphertext_hex)
        cipher = DES3.new(key_bytes, DES3.MODE_ECB)
        decrypted_padded = cipher.decrypt(ciphertext)
        decrypted_message = unpad(decrypted_padded, DES3.block_size).decode('utf-8')
        return decrypted_message
    except Exception as e:
        return f"Decryption failed: {str(e)}"

def validate_3des_key(key):
    if len(key) < 16:
        return False, "Key too short. Minimum 16 characters required for 3DES."

    if len(set(key[:8])) == 1 or len(set(key[8:16])) == 1:
        return False, "Weak key detected. Avoid using same character repeatedly."

    return True, "Key is valid."

def main():
    print("Triple DES Encryption/Decryption System")

    print()

    while True:
        choice = input("Enter encrypt or decrypt using 3DES cipher or exit out of prg: ")

        if choice == "encrypt":
            message = input("Enter plain text: ")
            key = input("Enter key (24 characters recommended): ")

            is_valid, validation_msg = validate_3des_key(key)
            if not is_valid:
                print("Key validation:", validation_msg)
                print("Using padded/truncated key for demonstration.")

            result = encrypt_3des(message, key)

            if len(key) < 24:
                actual_key = key.ljust(24, '0')
            elif len(key) > 24:
                actual_key = key[:24]
            else:
                actual_key = key

            print("Key used:", actual_key)
            print("Key length:", len(actual_key), "characters (", len(actual_key) * 8, "bits )")

        elif choice == "decrypt":
            ciphertext_hex = input("Enter ciphertext (in hex): ")
            key = input("Enter key (24 characters): ")

            is_valid, validation_msg = validate_3des_key(key)
            if not is_valid:
                print("Key validation:", validation_msg)

            result = decrypt_3des(ciphertext_hex, key)

            if len(key) < 24:
                actual_key = key.ljust(24, '0')
            elif len(key) > 24:
                actual_key = key[:24]
            else:
                actual_key = key

            print("Key used:", actual_key)
            print("Key length:", len(actual_key), "characters (", len(actual_key) * 8, "bits )")


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