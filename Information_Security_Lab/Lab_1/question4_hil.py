import numpy as np

def process_text(text, block_size, pad_char='X'):
    # Remove non-letters except spaces, make uppercase
    text = ''.join([c for c in text.upper() if c.isalpha() or c == ' '])
    result = []
    block = ''
    for c in text:
        if c == ' ':
            if block:
                # pad the current block if incomplete
                block = block.ljust(block_size, pad_char)
                result.append(block)
                block = ''
            result.append(' ')
        else:
            block += c
            if len(block) == block_size:
                result.append(block)
                block = ''
    if block:
        block = block.ljust(block_size, pad_char)
        result.append(block)
    return result

def text_block_to_numbers(block):
    return [ord(c) - ord('A') for c in block]

def numbers_to_text_block(nums):
    return ''.join([chr((n % 26) + ord('A')) for n in nums])

def matrix_mod_inv(matrix, modulus):
    det = int(round(np.linalg.det(matrix))) % modulus
    det_inv = None
    for i in range(1, modulus):
        if (det * i) % modulus == 1:
            det_inv = i
            break
    if det_inv is None:
        raise ValueError("Matrix is not invertible modulo {}".format(modulus))
    # Find matrix of cofactors, transpose (adjugate), multiply by det_inv and mod
    matrix_modulus_inv = (
        det_inv * np.round(det * np.linalg.inv(matrix)).astype(int) % modulus
    ) % modulus
    return matrix_modulus_inv

def hill_encrypt(plain, key_matrix):
    n = key_matrix.shape[0]
    blocks = process_text(plain, n)
    result = []
    for block in blocks:
        if block == ' ':
            result.append(' ')
        else:
            vec = np.array(text_block_to_numbers(block))
            enc = np.dot(key_matrix, vec) % 26
            result.append(numbers_to_text_block(enc))
    return ''.join(result)

def hill_decrypt(cipher, key_matrix):
    n = key_matrix.shape[0]
    inv_matrix = matrix_mod_inv(key_matrix, 26)
    blocks = process_text(cipher, n)
    result = []
    for block in blocks:
        if block == ' ':
            result.append(' ')
        else:
            vec = np.array(text_block_to_numbers(block))
            dec = np.dot(inv_matrix, vec) % 26
            result.append(numbers_to_text_block(dec))
    return ''.join(result).rstrip('X')

def get_matrix_from_input(size):
    print(f"Enter the {size}x{size} key matrix, row by row:")
    data = []
    for r in range(size):
        while True:
            row = input(f"Row {r+1} (space-separated numbers): ").strip()
            row_data = row.split()
            if len(row_data) != size:
                print("Incorrect number of elements. Please try again.")
                continue
            try:
                data.append([int(num) for num in row_data])
                break
            except ValueError:
                print("Please enter valid integers.")
    return np.array(data)

def menu():
    key_matrix = None
    n = None
    while True:
        print("\nHill Cipher Menu:")
        print("1. Set Key Matrix")
        print("2. Encrypt Message")
        print("3. Decrypt Message")
        print("4. Exit")
        choice = input("Enter your choice (1/2/3/4): ")

        if choice == '1':
            n = int(input("Enter the matrix size n (for n x n): "))
            key_matrix = get_matrix_from_input(n)
            print("Key matrix set.")
        elif choice == '2':
            if key_matrix is None:
                print("Please set the key matrix first (option 1).")
                continue
            plain = input("Enter the message to encrypt: ")
            cipher = hill_encrypt(plain, key_matrix)
            print("Encrypted Message:", cipher)
        elif choice == '3':
            if key_matrix is None:
                print("Please set the key matrix first (option 1).")
                continue
            cipher = input("Enter the message to decrypt: ")
            try:
                plain = hill_decrypt(cipher, key_matrix)
                print("Decrypted Message:", plain)
            except Exception as e:
                print("Error:", e)
        elif choice == '4':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    menu()