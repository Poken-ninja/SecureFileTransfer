# 🔐 Secure File Transfer System

This project securely encrypts and transfers files using a **hybrid cryptographic approach** combining **AES (symmetric)** and **RSA (asymmetric)** algorithms.

![Python Version](https://img.shields.io/badge/Python-3.12-blue)
![Library](https://img.shields.io/badge/PyCryptodome-✅-green)
![License](https://img.shields.io/badge/Status-Active-brightgreen)

---

## 📦 Features

- 🔒 AES file encryption using `PyCryptodome` (EAX mode)
- 🔑 RSA public key encryption for secure AES key sharing (coming soon)
- 💼 Clean virtual environment setup
- 🧑‍🤝‍🧑 Team-friendly with `requirements.txt` and `.gitignore`

---

## ⚙️ Setup Instructions

### 🧰 1. Clone the Repository

```bash
git clone https://github.com/Poken-ninja/SecureFileTransfer.git
cd SecureFileTransfer


# 🔐 Secure File Transfer System (AES + RSA)

This project demonstrates a **hybrid encryption model** using **AES (symmetric)** and **RSA (asymmetric)** encryption techniques to securely encrypt and transfer files.

## 📅 Day 1 – AES vs RSA Basics

### 🎯 Goal:
Understand why both **AES** and **RSA** are used together in secure systems.

### 🔑 Key Concepts:

| Algorithm | Type         | Purpose                       | Speed     |
|-----------|--------------|-------------------------------|-----------|
| AES       | Symmetric    | Encrypts the actual file/data | Fast      |
| RSA       | Asymmetric   | Encrypts the AES key          | Slower    |

### 🎥 Videos:
- [AES Encryption Explained (Computerphile)](https://www.youtube.com/watch?v=O4xNJsjtN6E)
- [RSA Encryption Explained (Computerphile)](https://www.youtube.com/watch?v=GSIDS_lvRv4)

### 📖 Article:
- [GeeksforGeeks: AES vs RSA](https://www.geeksforgeeks.org/difference-between-symmetric-and-asymmetric-key-encryption)

### ✅ Outcome:
By the end of Day 1, we understand:
- Why AES is used for fast file encryption
- Why RSA is used to securely send the AES key
- The fundamentals of symmetric vs. asymmetric encryption

---

## 📅 Day 2 – AES File Encryption (Symmetric)

### 🎯 Goal:
Implement basic AES encryption in Python using `pycryptodome`.

### 📦 Requirements:
```bash
pip install pycryptodome

🧪 2. Create a Virtual Environment
bash

python -m venv venv
▶️ Activate the venv
Windows:

bash


.\venv\Scripts\activate

Mac/Linux:

bash

source venv/bin/activate
📥 3. Install Dependencies
bash

pip install -r requirements.txt
🔄 Update Dependencies
Anytime you install new packages:

bash

pip freeze > requirements.txt
📁 Project Structure
pgsql

SecureFileTransfer/
├── encrypt.py
├── decrypt.py (coming soon)
├── key.bin
├── encrypted.bin
├── myfile.txt
├── requirements.txt
├── .gitignore
└── README.md
🤝 Team Notes
❗ Don’t upload venv/ to GitHub

✅ Always activate your virtual environment before running scripts

🔁 Use pip freeze > requirements.txt after changes

📚 Requirements
Python 3.12+

pycryptodome library
