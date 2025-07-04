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
