# 🔐 Secure File Transfer System (AES + RSA)

This project demonstrates a **hybrid encryption model** using **AES (symmetric)** and **RSA (asymmetric)** encryption techniques to securely encrypt and transfer files.

![Python Version](https://img.shields.io/badge/Python-3.12-blue)
![Library](https://img.shields.io/badge/PyCryptodome-✅-green)
![CI](https://github.com/Poken-ninja/SecureFileTransfer/actions/workflows/python.yml/badge.svg)
![License](https://img.shields.io/badge/Status-Active-brightgreen)

---

## 📦 Features

- 🔒 AES file encryption using `PyCryptodome` (EAX mode)
- 🔑 RSA public key encryption for secure AES key sharing *(coming soon)*
- 🧪 Password strength checker before key generation
- 📄 Automatic encryption logs to `encryption_log.txt`
- 🗂️ Backup original files before overwriting
- ⛔ Skips `.enc`, `.py`, and `.bak` files during encryption
- 💼 Virtual environment ready (`venv/` is ignored)
- 🤝 Team-friendly with `requirements.txt` and `.gitignore`

---

## ⚙️ Setup Instructions

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/Poken-ninja/SecureFileTransfer.git
cd SecureFileTransfer
```

### 2️⃣ Create & Activate Virtual Environment
<details>
<summary>🧪 Windows</summary>

```bash
python -m venv venv
.\venv\Scripts\activate
```
</details>

<details>
<summary>🧪 macOS/Linux</summary>

```bash
python3 -m venv venv
source venv/bin/activate
```
</details>

### 3️⃣ Install Dependencies
```bash
pip install -r requirements.txt
```

### 🔄 Update Requirements Anytime
```bash
pip freeze > requirements.txt
```

---

## 📁 Project Structure
```
SecureFileTransfer/
├── main.py              # Main encryption/decryption logic
├── requirements.txt     # Dependencies
├── .gitignore           # Ignores venv/, .enc, etc.
├── README.md            # Project documentation
├── encryption_log.txt   # Log of all encryption/decryption events
└── test.txt             # Example file to try
```

---

## 🔐 Encryption Flow

### 🔁 Encrypt/Decrypt ALL files (batch mode)
```python
encrypt_all_files()  # Encrypts all non-Python, non-.enc files

decrypt_all_files()  # Decrypts all .enc files
```

### 🧠 Smart Features
- ✅ Password must be strong: min 8 chars, uppercase, lowercase, digit, special char
- 📝 Every encryption/decryption is logged
- 🔁 Automatic `.bak` backup before file overwrite
- ❌ `.enc` files skipped from backup and re-encryption

---

## 📚 Libraries Used

| Library        | Purpose                                                      |
|----------------|--------------------------------------------------------------|
| `pycryptodome` | Cryptographic algorithms (AES, RSA)                          |
| `hashlib`      | Generates a strong key from password using SHA256           |
| `os`/`os.path` | File traversal, verification, and path joining              |
| `colorama`     | Terminal output colorization                                |
| `datetime`     | Timestamping logs                                           |
| `re`           | Regex for password validation                               |

---

## ✅ Continuous Integration (CI)

This repo uses **GitHub Actions** to automatically check Python syntax on every push.

### 📄 `.github/workflows/python.yml`
```yaml
name: Python Lint Check

on: [push, pull_request]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.12'

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install pycodestyle

      - name: Run pycodestyle
        run: |
          pycodestyle *.py --max-line-length=120
```

Add this file at:
```
SecureFileTransfer/.github/workflows/python.yml
```

---

## ✅ Contribution Guidelines

- 📌 Always activate virtual environment before running
- 🔒 Don't commit secrets or real data files
- 🧪 Run tests before pushing changes
- 📋 Use descriptive commit messages


## 👥 Contributors

- [**Poken-ninja**](https://github.com/Poken-ninja) – Project Lead  
- [**RyJohn1**](https://github.com/RyJohn1) – Contributor
  with help from AI (ChatGPT) and Somnath Paul

---

## 📜 License
MIT License – use freely with credit.
