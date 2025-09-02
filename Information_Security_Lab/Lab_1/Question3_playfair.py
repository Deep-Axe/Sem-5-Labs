
def create_playfair_matrix(key):
    """Create a 5x5 Playfair matrix from the provided key.

    Steps:
    1) Deduplicate characters in the key while preserving order.
    2) Replace 'J' with 'I' (I/J are merged in 5x5 Playfair).
    3) Fill remaining cells with the rest of the alphabet (A-Z, excluding J).

    Args:
        key (str): The encryption/decryption key (assumed uppercase by caller).

    Returns:
        list[list[str]]: A 5x5 matrix represented as a list of rows.
    """
    # Remove duplicate letters from the key while keeping first occurrences
    key = "".join(sorted(set(key), key=lambda x: key.index(x)))
    # Merge 'J' into 'I' to fit the 25-letter matrix convention
    key = key.replace('J', 'I')
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    # Build a flat list of 25 characters, starting with the unique key chars
    matrix = []
    seen = set()
    for char in key:
        if char not in seen:
            seen.add(char)
            matrix.append(char)
    # Fill remaining slots with alphabet letters not yet used
    for char in alphabet:
        if char not in seen:
            seen.add(char)
            matrix.append(char)
    # Convert the flat list into a 5x5 matrix (list of 5 rows)
    return [matrix[i:i + 5] for i in range(0, 25, 5)]

def preprocess_message(message):
    """Normalize plaintext/ciphertext and split into digraphs.

    Rules used:
    - Remove spaces and uppercase the message.
    - Split into pairs (digraphs).
    - If a pair has repeated letters (e.g., AA), insert 'X' after the first
      letter to separate them (AX, then continue from the second A).
    - If the final length is odd, pad the last letter with 'X'.

    Args:
        message (str): Input message.

    Returns:
        list[str]: List of 2-character digraphs.
    """
    message = message.replace(" ", "").upper()
    digraphs = []
    i = 0
    while i < len(message):
        if i + 1 < len(message) and message[i] == message[i + 1]:
            # Repeated letters in the same digraph -> insert 'X' after the first
            digraphs.append(message[i] + 'X')
            i += 1
        elif i + 1 < len(message):
            # Normal pair
            digraphs.append(message[i] + message[i + 1])
            i += 2
        else:
            # Odd final length -> pad with 'X'
            digraphs.append(message[i] + 'X')
            i += 1
    return digraphs

def find_position(matrix, char):
    """Find the (row, col) position of a character in the 5x5 matrix.

    Args:
        matrix (list[list[str]]): The 5x5 Playfair matrix.
        char (str): A single uppercase character expected to exist in the matrix.

    Returns:
        tuple[int, int]: (row_index, col_index)

    Raises:
        ValueError: If the character is not found in the matrix.
    """
    for row in range(5):
        if char in matrix[row]:
            return row, matrix[row].index(char)
    raise ValueError(f"Character '{char}' not found in matrix")


def playfair_cipher(key, message, mode='encrypt'):
    """Encrypt or decrypt a message using the Playfair cipher.
    Args:
        key (str): The key to construct the Playfair matrix. Uppercased here.
        message (str): The plaintext (for encryption) or ciphertext (for decryption).
        mode (str): 'encrypt' or 'decrypt'. Defaults to 'encrypt'.

    Returns:
        str: The resulting ciphertext (encrypt) or plaintext (decrypt).
    """
    matrix = create_playfair_matrix(key.upper())
    digraphs = preprocess_message(message)
    result = []

    for digraph in digraphs:
        first, second = digraph[0], digraph[1]
        r1, c1 = find_position(matrix, first)
        r2, c2 = find_position(matrix, second)

        if r1 == r2:
            # Same row: shift columns
            if mode == 'encrypt':
                result.append(matrix[r1][(c1 + 1) % 5])
                result.append(matrix[r2][(c2 + 1) % 5])
            else:
                result.append(matrix[r1][(c1 - 1) % 5])
                result.append(matrix[r2][(c2 - 1) % 5])
        elif c1 == c2:
            # Same column: shift rows
            if mode == 'encrypt':
                result.append(matrix[(r1 + 1) % 5][c1])
                result.append(matrix[(r2 + 1) % 5][c2])
            else:
                result.append(matrix[(r1 - 1) % 5][c1])
                result.append(matrix[(r2 - 1) % 5][c2])
        else:
            # Rectangle rule: swap columns (other corners of the rectangle)
            result.append(matrix[r1][c2])
            result.append(matrix[r2][c1])

    result = ''.join(result)

    if mode == 'decrypt':
        # Attempt to remove padding 'X' added during encryption/preprocessing.
        # Heuristic: if the text ends with 'X' and the preceding two letters
        # indicate it was a filler for a doubled letter, drop the trailing 'X'.
      
        if result.endswith('X') and len(result) > 1:
            # Potential edge case for short strings (len < 3).
            # Consider guarding with `len(result) >= 3` if you want to avoid
            # IndexError for very short inputs.
            if result[-2] == result[-3]:
                result = result[:-1]
        # Also strip any trailing 'X' padding that might remain
        result = result.rstrip('X')

    return result


def menu():
    """Interactive command-line menu for encrypting/decrypting messages."""
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
    # Launch the interactive menu when executed as a script
    menu()
