import time
import binascii
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


def test_des(message, iterations=1000):
    key = b"TESTKEY1"  # 8 bytes for DES
    message_bytes = message.encode('utf-8')

    start_time = time.time()
    for i in range(iterations):
        cipher = DES.new(key, DES.MODE_ECB)
        padded_message = pad(message_bytes, DES.block_size)
        ciphertext = cipher.encrypt(padded_message)
    encrypt_time = time.time() - start_time

    start_time = time.time()
    for i in range(iterations):
        cipher = DES.new(key, DES.MODE_ECB)
        decrypted = unpad(cipher.decrypt(ciphertext), DES.block_size)
    decrypt_time = time.time() - start_time

    return encrypt_time, decrypt_time, ciphertext


def test_aes256(message, iterations=1000):
    key = get_random_bytes(32)
    iv = get_random_bytes(16)
    message_bytes = message.encode('utf-8')

    start_time = time.time()
    for i in range(iterations):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(message_bytes, AES.block_size)
        ciphertext = cipher.encrypt(padded_message)
    encrypt_time = time.time() - start_time

    start_time = time.time()
    for i in range(iterations):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
    decrypt_time = time.time() - start_time

    return encrypt_time, decrypt_time, ciphertext


def main():
    message = "Performance Testing of Encryption Algorithms"
    iterations = 1000

    print("DES vs AES-256")
    print("Message:", message)
    print("Iterations:", iterations)
    print()

    print("DES")
    des_encrypt_time, des_decrypt_time, des_ciphertext = test_des(message, iterations)

    print("DES Results:")
    print(f"  Encryption time: {des_encrypt_time:.8f} seconds")
    print(f"  Decryption time: {des_decrypt_time:.8f} seconds")
    print(f"  Total time: {des_encrypt_time + des_decrypt_time:.8f} seconds")
    print(f"  Ciphertext (hex): {binascii.hexlify(des_ciphertext).decode().upper()}")
    print()

    print("AES-256")
    aes_encrypt_time, aes_decrypt_time, aes_ciphertext = test_aes256(message, iterations)

    print("AES-256 Results:")
    print(f"  Encryption time: {aes_encrypt_time:.8f} seconds")
    print(f"  Decryption time: {aes_decrypt_time:.8f} seconds")
    print(f"  Total time: {aes_encrypt_time + aes_decrypt_time:.8f} seconds")
    print(f"  Ciphertext (hex): {binascii.hexlify(aes_ciphertext).decode().upper()}")
    print()

    print("Comparison:")

    if des_encrypt_time < aes_encrypt_time:
        ratio = aes_encrypt_time / des_encrypt_time
        print(f"  DES encryption is {ratio:.6f}x faster than AES-256")
    else:
        ratio = des_encrypt_time / aes_encrypt_time
        print(f"  AES-256 encryption is {ratio:.6f}x faster than DES")

    if des_decrypt_time < aes_decrypt_time:
        ratio = aes_decrypt_time / des_decrypt_time
        print(f"  DES decryption is {ratio:.6f}x faster than AES-256")
    else:
        ratio = des_decrypt_time / aes_decrypt_time
        print(f"  AES-256 decryption is {ratio:.6f}x faster than DES")

    total_des = des_encrypt_time + des_decrypt_time
    total_aes = aes_encrypt_time + aes_decrypt_time

    if total_des < total_aes:
        ratio = total_aes / total_des
        print(f"  DES overall is {ratio:.6f}x faster than AES-256")
    else:
        ratio = total_des / total_aes
        print(f"  AES-256 overall is {ratio:.6f}x faster than DES")



if __name__ == "__main__":
    main()