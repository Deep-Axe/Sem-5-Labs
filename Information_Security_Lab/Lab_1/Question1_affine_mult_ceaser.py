# ---------------- Additive (Caesar) Cipher ----------------
def caesar_encrypt(name, s):
    res = ""
    for i in range(len(name)):
        char = name[i]
        if char.isupper():
            res += chr((ord(char) + s - 65) % 26 + 65)
        elif char.islower():
            res += chr((ord(char) + s - 97) % 26 + 97)
        else:
            res += char
    return res


def caesar_decrypt(name, s):
    res = ""
    for i in range(len(name)):
        char = name[i]
        if char.isupper():
            res += chr((ord(char) - s - 65) % 26 + 65)
        elif char.islower():
            res += chr((ord(char) - s - 97) % 26 + 97)
        else:
            res += char
    return res


# ---------------- Multiplicative Cipher ----------------
def mult_encrypt(name, s):
    res = ""
    for i in range(len(name)):
        char = name[i]
        if char.isupper():
            res += chr(((ord(char) - 65) * s) % 26 + 65)
        elif char.islower():
            res += chr(((ord(char) - 97) * s) % 26 + 97)
        else:
            res += char
    return res


def mult_decrypt(name, s):
    res = ""
    try:
        # Compute modular inverse of key under mod 26
        multiplicative_inverse = pow(s, -1, 26)
    except ValueError:
        return "Invalid key, no modular inverse exists"

    for i in range(len(name)):
        char = name[i]
        if char.isupper():
            res += chr(((ord(char) - 65) * multiplicative_inverse) % 26 + 65)
        elif char.islower():
            res += chr(((ord(char) - 97) * multiplicative_inverse) % 26 + 97)
        else:
            res += char
    return res


# ---------------- Affine Cipher ----------------
def affine_encrypt(name, a, b):
    res = ""
    for i in range(len(name)):
        char = name[i]
        if char.isupper():
            res += chr((((ord(char) - 65) * a + b) % 26) + 65)
        elif char.islower():
            res += chr((((ord(char) - 97) * a + b) % 26) + 97)
        else:
            res += char
    return res


def affine_decrypt(name, a, b):
    # Compute modular inverse of multiplicative key 'a'
    try:
        multiplicative_inverse = pow(a, -1, 26)
    except ValueError:
        return "Invalid key, no modular inverse exists"

    res = ""
    for i in range(len(name)):
        char = name[i]
        if char.isupper():
            res += chr((((ord(char) - 65 - b) * multiplicative_inverse) % 26) + 65)
        elif char.islower():
            res += chr((((ord(char) - 97 - b) * multiplicative_inverse) % 26) + 97)
        else:
            res += char
    return res


# ---------------- Main Driver ----------------
def main():
    while True:
        print("\nChoose the cipher:")
        print("1. Additive (Caesar) Cipher")
        print("2. Multiplicative Cipher")
        print("3. Affine Cipher")
        print("4. Exit")

        choice = input("Enter choice (1/2/3/4): ")

        if choice == "1":  # Caesar cipher
            action = input("Do you want to encrypt or decrypt? ").strip().lower()
            text = input("Enter the text: ")
            key = int(input("Enter the additive (shift) key: "))

            if action == "encrypt":
                result = caesar_encrypt(text, key)
            elif action == "decrypt":
                result = caesar_decrypt(text, key)
            else:
                print("Invalid action")
                continue

        elif choice == "2":  # Multiplicative cipher
            action = input("Do you want to encrypt or decrypt? ").strip().lower()
            text = input("Enter the text: ")
            key = int(input("Enter the multiplicative key: "))

            if action == "encrypt":
                result = mult_encrypt(text, key)
            elif action == "decrypt":
                result = mult_decrypt(text, key)
            else:
                print("Invalid action")
                continue

        elif choice == "3":  # Affine cipher
            action = input("Do you want to encrypt or decrypt? ").strip().lower()
            text = input("Enter the text: ")
            a = int(input("Enter the multiplicative key (a): "))
            b = int(input("Enter the additive key (b): "))

            if action == "encrypt":
                result = affine_encrypt(text, a, b)
            elif action == "decrypt":
                result = affine_decrypt(text, a, b)
            else:
                print("Invalid action")
                continue

        elif choice == "4":
            print("Exiting program...")
            break
        else:
            print("Invalid choice, please try again.")
            continue

        print("Result:", result)


if __name__ == "__main__":
    main()
