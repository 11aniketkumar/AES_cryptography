from Crypto import Random
from Crypto.Cipher import AES
import os
import os.path
import time


class Encryptor:
    def __init__(self, key):
        self.key = key

    def pad(self, s):
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

    def encrypt(self, message, key, key_size=256):
        message = self.pad(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(message)

    def encrypt_file(self, file_name):
        with open(file_name, 'rb') as fo:
            plaintext = fo.read()
        enc = self.encrypt(plaintext, self.key)
        with open(file_name + ".enc", 'wb') as fo:
            fo.write(enc)
        os.remove(file_name)

    def decrypt(self, ciphertext, key):
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")

    def decrypt_file(self, file_name):
        with open(file_name, 'rb') as fo:
            ciphertext = fo.read()
        dec = self.decrypt(ciphertext, self.key)
        with open(file_name[:-4], 'wb') as fo:
            fo.write(dec)
        os.remove(file_name)

    def getAllFiles(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        dirs = []
        for dirName, subdirList, fileList in os.walk(dir_path):
            for fname in fileList:
                if (fname != 'script.py' and fname != 'data.txt.enc'):
                    dirs.append(os.path.join(dirName, fname))
        return dirs

    def encrypt_all_files(self):
        dirs = self.getAllFiles()
        for file_name in dirs:
            self.encrypt_file(file_name)

    def decrypt_all_files(self):
        dirs = self.getAllFiles()
        for file_name in dirs:
            self.decrypt_file(file_name)

def menu():
    choice = input("""
    1: Encrypt a file
    2: Decrypt a file
    3: Encrypt all files in the current directory
    4: Decrypt all files in the current directory
    5: Exit
    
    Please enter your choice: """)

    return choice


if __name__ == "__main__":
    key = input("Enter encryption key: ").encode('utf-8')
    enc = Encryptor(key)

    while True:
        choice = menu()

        if choice == "1":
            file_to_encrypt = input("Enter the name of the file to encrypt: ")
            enc.encrypt_file(file_to_encrypt)

        elif choice == "2":
            file_to_decrypt = input("Enter the name of the file to decrypt: ")
            enc.decrypt_file(file_to_decrypt)

        elif choice == "3":
            enc.encrypt_all_files()
            print("All files encrypted.")

        elif choice == "4":
            enc.decrypt_all_files()
            print("All files decrypted.")

        elif choice == "5":
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please enter a valid option.")
