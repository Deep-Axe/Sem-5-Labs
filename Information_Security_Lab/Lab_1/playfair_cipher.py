def create_playfair_matrix(key):
    key = "".join(sorted(set(key), key=lambda x: key.index(x)))
    key = key.replace('J', 'I')
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"

    matrix = []
    seen = set()
    for char in key:
        if char not in seen:
            seen.add(char)
            matrix.append(char)

    for char in alphabet:
        if char not in seen:
            seen.add(char)
            matrix.append(char)

    return [matrix[i:i + 5] for i in range(0, 25, 5)]

def preprocess_message(message):
    message = message.replace(" ", "").upper()
    digraphs = []
    i = 0
    while i < len(message):
        if i + 1 < len(message) and message[i] == message[i + 1]:
            digraphs.append(message[i] + 'X')
            i += 1
        elif i + 1 < len(message):
            digraphs.append(message[i] + message[i + 1])
            i += 2
        else:
            digraphs.append(message[i] + 'X')
            i += 1
    return digraphs

def find_position(matrix, char):
    for row in range(5):
        if char in matrix[row]:
            return row, matrix[row].index(char)
    return None


def playfair_cipher(key, message, mode='encrypt'):
    matrix = create_playfair_matrix(key.upper())
    digraphs = preprocess_message(message)
    result = []

    for digraph in digraphs:
        first, second = digraph[0], digraph[1]
        r1, c1 = find_position(matrix, first)
        r2, c2 = find_position(matrix, second)

        if r1 == r2:
            if mode == 'encrypt':
                result.append(matrix[r1][(c1 + 1) % 5])
                result.append(matrix[r2][(c2 + 1) % 5])
            else:
                result.append(matrix[r1][(c1 - 1) % 5])
                result.append(matrix[r2][(c2 - 1) % 5])
        elif c1 == c2:
            if mode == 'encrypt':
                result.append(matrix[(r1 + 1) % 5][c1])
                result.append(matrix[(r2 + 1) % 5][c2])
            else:
                result.append(matrix[(r1 - 1) % 5][c1])
                result.append(matrix[(r2 - 1) % 5][c2])
        else:
            result.append(matrix[r1][c2])
            result.append(matrix[r2][c1])

    result = ''.join(result)

    if mode == 'decrypt':
        if result.endswith('X') and len(result) > 1:
            if result[-2] == result[-3]:
                result = result[:-1]
        result = result.rstrip('X')

    return result


def menu():
    while True:
        print("\nPlayfair Cipher Menu:")
        print("1. Encrypt Message")
        print("2. Decrypt Message")
        print("3. Exit")

        choice = input("Enter your choice (1/2/3): ")

        if choice == '1':
            key = input("Enter the key: ")
            message = input("Enter the message to encrypt: ")
            print("Encrypted Message: ", playfair_cipher(key, message, mode='encrypt'))
        elif choice == '2':
            key = input("Enter the key: ")
            message = input("Enter the message to decrypt: ")
            print("Decrypted Message: ", playfair_cipher(key, message, mode='decrypt'))
        elif choice == '3':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__=="__main__":
    menu()
