def encrypt(name, a,b):
    res = ""
    for i in range(len(name)):
        char = name[i]
        if char.isupper():
            res += chr((((ord(char) - 65) * a) + b) % 26 + 65)
        elif char.islower():
            res += chr((((ord(char) - 97) * a) + b) % 26 + 97)
        else:
            res += char
    return res

def decrypt(name, a,b):
    res = ""
    try:
        multiplicative_inverse = pow(a, -1, 26)
    except ValueError:
        return "Invalid key, no modular inverse exists"
    for i in range(len(name)):
        char = name[i]
        if char.isupper():
            res += chr((((ord(char) - 65) - b) * multiplicative_inverse) % 26 + 65)
        elif char.islower():
            res += chr((((ord(char) - 97) - b) * multiplicative_inverse) % 26 + 97)
        else:
            res += char
    return res

def main():
    while True:
        choice = input("Enter encrypt or decrypt using affine cipher or exit out of prg: ")
        if choice == "encrypt":
            name = input("Enter plain Text : ")
            a = int(input("Enter multiplicative key: "))
            b = int(input("Enter additive key: "))
            result = encrypt(name, a,b)
        elif choice == "decrypt":
            name = input("Enter plain Text : ")
            a = int(input("Enter multiplicative key: "))
            b = int(input("Enter additive key: "))
            result = decrypt(name, a, b)
        elif choice == "exit":
            break
        else:
            print("invalid choice")
            continue
        print("Resultant encryption/decryption is ", result)

if __name__ == '__main__':
    main()

