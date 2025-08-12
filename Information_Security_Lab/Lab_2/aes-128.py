import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

def encrypt_aes(message, key):
    try:
        if len(key) == 32:
            key_bytes = binascii.unhexlify(key)
        else:
            if len(key) < 16:
                key = key.ljust(16, '0')
            elif len(key) > 16:
                key = key[:16]
            key_bytes = key.encode('utf-8')

        message_bytes = message.encode('utf-8')

        iv = os.urandom(16)

        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)

        padded_message = pad(message_bytes, AES.block_size)
        ciphertext = cipher.encrypt(padded_message)

        encrypted_data = iv + ciphertext
        ciphertext_hex = binascii.hexlify(encrypted_data).decode('utf-8').upper()

        return ciphertext_hex

    except Exception as e:
        return f"Encryption failed: {str(e)}"


def decrypt_aes(ciphertext_hex, key):
    try:
        if len(key) == 32:
            key_bytes = binascii.unhexlify(key)
        else:
            if len(key) < 16:
                key = key.ljust(16, '0')
            elif len(key) > 16:
                key = key[:16]
            key_bytes = key.encode('utf-8')

        encrypted_data = binascii.unhexlify(ciphertext_hex)

        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)

        decrypted_padded = cipher.decrypt(ciphertext)
        decrypted_message = unpad(decrypted_padded, AES.block_size).decode('utf-8')

        return decrypted_message

    except Exception as e:
        return f"Decryption failed: {str(e)}"

def main():

    print("Key should be 32 hex characters for AES-128")
    print()

    while True:
        choice = input("Enter encrypt or decrypt using AES-128 cipher or exit out of prg: ")

        if choice == "encrypt":
            message = input("Enter plain text: ")
            key = input("Enter key (32 hex chars or 16 string chars): ")
            result = encrypt_aes(message, key)

            if len(key) == 32:
                print("Key used (hex):", key)
            else:
                actual_key = key.ljust(16, '0') if len(key) < 16 else key[:16]
                print("Key used (string):", actual_key)
                print("Key used (hex):", binascii.hexlify(actual_key.encode()).decode().upper())

        elif choice == "decrypt":
            ciphertext_hex = input("Enter ciphertext (in hex): ")
            key = input("Enter key (32 hex chars or 16 string chars): ")
            result = decrypt_aes(ciphertext_hex, key)

            if len(key) == 32:
                print("Key used (hex):", key)
            else:
                actual_key = key.ljust(16, '0') if len(key) < 16 else key[:16]
                print("Key used (string):", actual_key)
                print("Key used (hex):", binascii.hexlify(actual_key.encode()).decode().upper())

        elif choice == "exit":
            break

        else:
            print("Invalid choice")
            continue

        print("Resultant encryption/decryption is:", result)
        print()


if __name__ == '__main__':
    main()