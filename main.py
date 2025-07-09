from Crypto.Cipher import AES
import hashlib
import os
from datetime import datetime
from colorama import Fore, init

#Initialize colorama for colored terminal output
init(autoreset=True)

#Constants
LOG_PATH = "encryption_activity.log"
BACKUP_SUFFIX = ".bak"
ENCRYPTED_SUFFIX = ".enc"

class SecureFileManager:
    def __init__(self, key):
        self.key = key

    def record_log(self, filename, action, status):
        """Logs all encryption/decryption events with timestamps."""
        with open(LOG_PATH, 'a') as log_file:
            log_file.write(f"[{datetime.now()}] {action.upper()} - {filename} - {status}\n")

    def create_backup(self, filepath):
        """Creates a backup of the original file before modifying it."""
        if not os.path.isfile(filepath):
            print(Fore.RED + f"File not found: {filepath}")
            return
        if filepath.endswith(ENCRYPTED_SUFFIX):
            return  # No need to back up already encrypted files
        with open(filepath, 'rb') as source, open(filepath + BACKUP_SUFFIX, 'wb') as dest:
            dest.write(source.read())

    def perform_encryption(self, raw_data):
        """Encrypts data using AES-EAX mode and returns ciphertext, tag, and cipher object."""
        cipher = AES.new(self.key, AES.MODE_EAX)
        encrypted_data, tag = cipher.encrypt_and_digest(raw_data)
        return encrypted_data, tag, cipher

    def perform_decryption(self, ciphertext, nonce, tag):
        """Attempts to decrypt and verify the integrity of encrypted data."""
        try:
            cipher = AES.new(self.key, AES.MODE_EAX, nonce)
            plain_data = cipher.decrypt_and_verify(ciphertext, tag)
            return plain_data.rstrip(b"\0")
        except ValueError:
            print(Fore.RED + "Decryption failed: Invalid key or corrupted data.")
            return None

    def encrypt_single_file(self, filepath):
        """Encrypts a single file, backs up original, and writes output with '.enc' extension."""
        if not os.path.isfile(filepath):
            print(Fore.RED + "File does not exist.")
            return
        self.create_backup(filepath)
        with open(filepath, 'rb') as file:
            plaintext = file.read()
        encrypted, tag, cipher = self.perform_encryption(plaintext)
        with open(filepath + ENCRYPTED_SUFFIX, 'wb') as output:
            output.write(cipher.nonce + tag + encrypted)
        self.record_log(filepath, "encrypt", "Success")
        if input("Delete original file? (y/n): ").lower() == 'y':
            os.remove(filepath)

    def decrypt_single_file(self, filepath):
        """Decrypts a file ending in '.enc' and restores it to its original form."""
        if not os.path.isfile(filepath):
            print(Fore.RED + "File not found.")
            return
        self.create_backup(filepath)
        with open(filepath, 'rb') as file:
            nonce = file.read(16)
            tag = file.read(16)
            ciphertext = file.read()
        decrypted = self.perform_decryption(ciphertext, nonce, tag)
        if decrypted is None:
            self.record_log(filepath, "decrypt", "Failed")
            return
        with open(filepath[:-4], 'wb') as output:
            output.write(decrypted)
        self.record_log(filepath, "decrypt", "Success")
        if input("Delete encrypted file? (y/n): ").lower() == 'y':
            os.remove(filepath)

    def collect_files(self, mode):
        """Collects file paths recursively for encryption or decryption."""
        current_dir = os.path.dirname(os.path.realpath(__file__))
        collected_files = []
        for root, subdirs, files in os.walk(current_dir, topdown=True):
            subdirs[:] = [d for d in subdirs if d not in ['venv', '.vscode']]
            for fname in files:
                path = os.path.join(root, fname)
                if mode == 'encrypt' and not fname.endswith(('.py', ENCRYPTED_SUFFIX)):
                    collected_files.append(path)
                elif mode == 'decrypt' and fname.endswith(ENCRYPTED_SUFFIX):
                    collected_files.append(path)
        return collected_files

    def encrypt_all(self):
        """Encrypts all eligible files in the project directory."""
        for f in self.collect_files('encrypt'):
            self.encrypt_single_file(f)

    def decrypt_all(self):
        """Decrypts all files in the project directory ending with '.enc'."""
        for f in self.collect_files('decrypt'):
            self.decrypt_single_file(f)

    @staticmethod
    def derive_key(password):
        """Generates a 256-bit AES key using SHA-256 hash of the password."""
        return hashlib.sha256(password.encode()).digest()


# Password validation function
def is_strong_password(pwd):
    """Checks if the password meets complexity standards."""
    import re
    if len(pwd) < 8:
        return False, "Minimum 8 characters required."
    if not re.search(r"[A-Z]", pwd):
        return False, "Must include an uppercase letter."
    if not re.search(r"[a-z]", pwd):
        return False, "Must include a lowercase letter."
    if not re.search(r"\d", pwd):
        return False, "Must include a number."
    if not re.search(r"[@$!%*?&]", pwd):
        return False, "Must include a special character (@$!%*?&)."
    return True, "Password is strong."


# Menu-driven interface
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def main():
    while True:
        pwd = input(Fore.GREEN + "Enter encryption key: ")
        confirm = input(Fore.GREEN + "Confirm key: ")
        if pwd != confirm:
            print(Fore.RED + "Key mismatch.")
            continue
        is_valid, msg = is_strong_password(pwd)
        if not is_valid:
            print(Fore.RED + msg)
            continue
        manager = SecureFileManager(SecureFileManager.derive_key(pwd))
        break

    while True:
        clear_screen()
        print(Fore.YELLOW + "\nSecure File Transfer System")
        print("1. Encrypt a file")
        print("2. Decrypt a file")
        print("3. Encrypt all files")
        print("4. Decrypt all files")
        print("5. Exit")

        try:
            option = int(input(Fore.CYAN + "Enter your choice: "))
        except ValueError:
            print(Fore.RED + "Invalid input. Use numbers only.")
            input("Press Enter to continue...")
            continue

        if option == 1:
            f = input("Enter path of file to encrypt: ")
            manager.encrypt_single_file(f)
        elif option == 2:
            f = input("Enter path of file to decrypt: ")
            manager.decrypt_single_file(f)
        elif option == 3:
            manager.encrypt_all()
        elif option == 4:
            manager.decrypt_all()
        elif option == 5:
            print(Fore.GREEN + "Exiting securely.")
            break
        else:
            print(Fore.RED + "Invalid choice.")
        input("Press Enter to return to menu...")

if __name__ == "__main__":
    main()
