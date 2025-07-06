from Crypto.Cipher import AES
import hashlib
import os
import os.path
from datetime import datetime
from colorama import Fore, init

init(autoreset=True)  # Initialize colorama

LOG_FILE = "encryption_log.txt"

class myEncryptor:
    def __init__(self, key) -> None:
        self.key = key

    def log_event(self, file_name, operation, status):
        with open(LOG_FILE, 'a') as log:
            log.write(f"[{datetime.now()}] {operation.upper()} - {file_name} - {status}\n")

    def backup_file(self, file_name):
        if not os.path.isfile(file_name):
            print(Fore.RED + f"File '{file_name}' does not exist.")
            return

        if file_name.endswith('.enc'):
            return  # Skip backup for encrypted files

        backup_name = file_name + ".bak"
        with open(file_name, 'rb') as original, open(backup_name, 'wb') as backup:
            backup.write(original.read())

    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return ciphertext, tag, cipher

    def decrypt(self, ciphertext, nonce, tag):
        cipher = AES.new(self.key, AES.MODE_EAX, nonce)
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext.rstrip(b"\0")
        except ValueError:
            print(Fore.RED + "Key incorrect or message corrupted")
            return None

    def encrypt_file(self, file_name):
        if not os.path.isfile(file_name):
            print(Fore.RED + "File not found!")
            return

        self.backup_file(file_name)

        with open(file_name, 'rb') as fo:
            plaintext = fo.read()

        ciphertext, tag, cipher = self.encrypt(plaintext)

        with open(file_name + ".enc", 'wb') as fo:
            fo.write(cipher.nonce)
            fo.write(tag)
            fo.write(ciphertext)

        self.log_event(file_name, "encrypt", "Success")

        confirm = input("Delete original file after encryption? (y/n): ").lower()
        if confirm == 'y':
            os.remove(file_name)

    def decrypt_file(self, file_name):
        if not os.path.isfile(file_name):
            print(Fore.RED + "File not found!")
            return

        self.backup_file(file_name)

        with open(file_name, 'rb') as fo:
            nonce = fo.read(16)
            tag = fo.read(16)
            ciphertext = fo.read()

        dec = self.decrypt(ciphertext, nonce, tag)
        if dec is None:
            self.log_event(file_name, "decrypt", "Failed")
            return

        with open(file_name[:-4], 'wb') as fo:
            fo.write(dec)

        self.log_event(file_name, "decrypt", "Success")

        confirm = input("Delete encrypted file after decryption? (y/n): ").lower()
        if confirm == 'y':
            os.remove(file_name)

    def getAllFiles(self, mode):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        exclude = set(['venv', '.vscode'])
        dirs = []

        for dirName, subdirList, fileList in os.walk(dir_path, topdown=True):
            subdirList[:] = [d for d in subdirList if d not in exclude]
            for fname in fileList:
                path = os.path.join(dirName, fname)
                if mode == 'e':
                    if not fname.endswith('.py') and not fname.endswith('.enc'):
                        dirs.append(path)
                elif mode == 'd':
                    if fname.endswith('.enc'):
                        dirs.append(path)
        return dirs

    def encrypt_all_files(self):
        dirs = self.getAllFiles(mode='e')
        for file_name in dirs:
            self.encrypt_file(file_name)

    def decrypt_all_files(self):
        dirs = self.getAllFiles(mode='d')
        for file_name in dirs:
            self.decrypt_file(file_name)

    @staticmethod
    def generate_key(password):
        return hashlib.sha256(password.encode('utf-8')).digest()

def password_strength(password):
    import re
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain an uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain a lowercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain a digit."
    if not re.search(r"[@$!%*?&]", password):
        return False, "Password must contain a special character (@$!%*?&)."
    return True, "Strong password."

clear = lambda: os.system('cls' if os.name == 'nt' else 'clear')

while True:
    password = str(input(Fore.GREEN + "Enter encryption / decryption key: "))
    repassword = str(input(Fore.GREEN + "Confirm your key: "))

    if password != repassword:
        print(Fore.RED + "Key mismatch!")
        continue

    valid, msg = password_strength(password)
    if not valid:
        print(Fore.RED + msg)
        continue

    enc = myEncryptor(myEncryptor.generate_key(password))
    break

while True:
    clear()
    print(Fore.YELLOW + "Menu:")
    print("1. Press '1' to encrypt a file.")
    print("2. Press '2' to decrypt a file.")
    print("3. Press '3' to encrypt all files.")
    print("4. Press '4' to decrypt all files.")
    print("5. Press '5' to exit.")

    try:
        choice = int(input(Fore.CYAN + "\nEnter your choice: "))
    except ValueError:
        print(Fore.RED + "Invalid input! Please enter a number.")
        input("Press Enter to continue...")
        continue

    if choice == 1:
        file_name = input("Enter file name to encrypt (with path if needed): ")
        enc.encrypt_file(file_name)
    elif choice == 2:
        file_name = input("Enter file name to decrypt (with path if needed): ")
        enc.decrypt_file(file_name)
    elif choice == 3:
        enc.encrypt_all_files()
    elif choice == 4:
        enc.decrypt_all_files()
    elif choice == 5:
        print(Fore.GREEN + "Exiting. Goodbye!")
        break
    else:
        print(Fore.RED + "Please select a valid option!")

    input("\nPress Enter to return to the menu...")
