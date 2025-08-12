import binascii
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad


def encrypt_des(message, key):

    if len(key) < 8:
        key = key.ljust(8, '0')
    elif len(key) > 8:
        key = key[:8]
    key_bytes = key.encode('utf-8')
    message_bytes = message.encode('utf-8')

    cipher = DES.new(key_bytes, DES.MODE_ECB)

    padded_message = pad(message_bytes, DES.block_size)
    ciphertext = cipher.encrypt(padded_message)

    ciphertext_hex = binascii.hexlify(ciphertext).decode('utf-8').upper()

    return ciphertext_hex


def decrypt_des(ciphertext_hex, key):
    try:
        if len(key) < 8:
            key = key.ljust(8, '0')
        elif len(key) > 8:
            key = key[:8]

        key_bytes = key.encode('utf-8')

        ciphertext = binascii.unhexlify(ciphertext_hex)

        cipher = DES.new(key_bytes, DES.MODE_ECB)

        decrypted_padded = cipher.decrypt(ciphertext)
        decrypted_message = unpad(decrypted_padded, DES.block_size).decode('utf-8')

        return decrypted_message

    except Exception as e:
        return f"Decryption failed: {str(e)}"


def main():
    print("DES Encryption/Decryption System")

    while True:
        choice = input("Enter encrypt or decrypt using DES cipher or exit out of prg: ")

        if choice == "encrypt":
            message = input("Enter plain text: ")
            key = input("Enter key (8 characters): ")
            result = encrypt_des(message, key)
            print("Key used:", key if len(key) == 8 else (key.ljust(8, '0') if len(key) < 8 else key[:8]))

        elif choice == "decrypt":
            ciphertext_hex = input("Enter ciphertext (in hex): ")
            key = input("Enter key (8 characters): ")
            result = decrypt_des(ciphertext_hex, key)
            print("Key used:", key if len(key) == 8 else (key.ljust(8, '0') if len(key) < 8 else key[:8]))

        elif choice == "exit":
            break

        else:
            print("Invalid choice")
            continue

        print("Resultant encryption/decryption is:", result)
        print()


if __name__ == '__main__':
    main()
