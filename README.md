# 📌 Project: ECDH Secure Messaging

## Introduction
This project implements a simple secure communication protocol where **Alice** sends a message to **Bob** without any pre-shared secret.  
The protocol combines **asymmetric cryptography** (Elliptic Curve Diffie-Hellman) with **symmetric encryption** (AES-GCM).

---

## 🔑 Protocol Overview
1. **Key generation**  
   - Bob creates a static key pair (**private key**, **public key**).  
   - Alice creates an **ephemeral** key pair for the message.  

2. **Key exchange (ECDH)**  
   - Alice computes a shared secret using her private key and Bob’s public key.  
   - Bob computes the same secret using his private key and Alice’s public key.  

3. **Key derivation (HKDF)**  
   - The raw ECDH secret is processed with **HKDF (SHA-256)** to derive a 128-bit symmetric key.  

4. **Encryption (AES-128-GCM)**  
   - Alice encrypts the plaintext with the derived key and a random **nonce** (12 bytes).  
   - She sends Bob the **ciphertext**, **nonce**, and her **public key**.  

5. **Decryption**  
   - Bob repeats the HKDF step to get the same symmetric key.  
   - Bob decrypts the ciphertext using AES-GCM, verifying both confidentiality and integrity.  

---

## 🛠️ Algorithms Used
- **Key exchange**: ECDH over curve **SECP256R1 (P-256)** (~128-bit security).  
- **Key derivation**: HKDF with SHA-256.  
- **Symmetric encryption**: AES-128-GCM (Authenticated Encryption with Associated Data).  
- **Language**: Python 3 with the `cryptography` library.  

---

## 📂 Files
- `ecdh_secure_message.py` → Full Python implementation with comments.  
- `it2022052_CRYPTOGRAPHY.pdf` → Documentation/report explaining the protocol and choices.  
- `README.md` → This file.  

---

## ▶ How to Run
1. Install dependencies:
   ```bash
   pip install cryptography
