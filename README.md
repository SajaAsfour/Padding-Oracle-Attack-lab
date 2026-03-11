# 🔐 Padding Oracle Attack Lab

## 📌 Overview

This project demonstrates the **Padding Oracle Attack** against a block cipher operating in **CBC mode with PKCS#7 padding**.
The experiment shows how an attacker can decrypt ciphertext **without knowing the encryption key**, simply by observing whether the padding of decrypted messages is valid or invalid. 

The lab is divided into two main parts:

* **Level 1 – Manual Padding Oracle Attack**
* **Level 2 – Automated Padding Oracle Attack using Python**

The experiment was conducted using the **SEED Security Labs environment** with Docker.

---

## 🎯 Objectives

The main goals of this lab are:

* Understand how **CBC mode encryption works**
* Learn how **PKCS#7 padding** is applied and validated
* Demonstrate how **padding validation leaks information**
* Perform a **byte-by-byte decryption attack**
* Automate the attack using a **Python script**

The attack proves that even secure cryptographic algorithms can become vulnerable if **error messages leak information**. 

---

## 🧪 Lab Environment

The lab environment is built using the **SEED Security Labs** setup.

### Setup Steps

1. Download the lab files from SEED Labs.
2. Extract `Labsetup.zip`.
3. Rename the folder to your student name.
4. Run the Docker environment.

```bash
docker-compose up
```

This command builds and launches the containers required for the padding oracle experiment. 

---

# ⚔️ Task 1 — Manual Padding Oracle Attack (Level 1)

## Concept

The attack modifies bytes in the previous ciphertext block to influence the decrypted padding of the next block.

By observing whether the server reports:

* **Valid Padding**
* **Invalid Padding**

we can deduce intermediate values and recover plaintext bytes.

---

## Attack Process

For each byte in the block:

1. Guess a byte value.
2. Modify the previous ciphertext block.
3. Send the ciphertext to the oracle.
4. Check if the padding is valid.
5. Compute intermediate value:

```
D[i] = guessed_byte ⊕ padding_value
```

6. Recover plaintext:

```
Plaintext = D ⊕ PreviousCipherBlock
```

This process is repeated **byte-by-byte from right to left**.

---

## Result of Manual Attack

The manual process successfully recovered part of the plaintext.

The recovered block contained:

* **13 bytes of actual data**
* **3 bytes of PKCS#7 padding (03 03 03)**

This confirmed correct decryption of the ciphertext block. 

---

# 🤖 Task 2 — Automated Padding Oracle Attack (Level 2)

Manual attacks are slow, so the process was automated using **Python**.

The script performs the following:

1. Connects to the **oracle server**
2. Receives the encrypted message
3. Splits it into blocks
4. Performs byte-by-byte padding oracle queries
5. Recovers the plaintext automatically

---

## Oracle Connection

The script connects to the oracle server:

```
IP: 10.9.0.80
Port: 6000
```

The server returns the encrypted message containing:

* Initialization Vector (IV)
* Ciphertext blocks

Example:

```
IV: f52f86d09a52a9e12a2937e16c62bdd4
Blocks: 3
```

---

## Automated Decryption

The script decrypts each block sequentially:

```
Block 1 → decrypted
Block 2 → decrypted
Block 3 → decrypted
```

Each block is decrypted **byte by byte using oracle responses**.

---

## Final Decrypted Message

After removing PKCS#7 padding and converting the bytes to text, the recovered message is:

```
(^_^)(^_^) The SEED Labs are great! (^_^)(^_^)
```

This confirms that the attack successfully decrypted the ciphertext **without the encryption key**. 

---

# 🛠 Technologies Used

* Python
* Docker
* SEED Security Labs
* CBC Encryption Mode
* PKCS#7 Padding
* Networking (TCP Socket Communication)

---

# 📂 Project Structure

```
Padding-Oracle-Attack
│
├── manual_attack.py              # Manual attack script
├── level2.py                     # Automated padding oracle attack
├── Asfour_1210737_TODO1.pdf      # Full lab report
└── README.md
```

---

# ⚠️ Security Implications

Padding oracle vulnerabilities can completely break encryption systems.

They allow attackers to:

* Decrypt sensitive information
* Recover secret messages
* Manipulate encrypted data

This attack highlights the importance of:

* **Proper error handling**
* **Authenticated encryption**
* **Avoiding padding error leaks**

---

# 👩‍💻 Author

**Saja Asfour**

---

# 📚 References

* SEED Security Labs – Padding Oracle Attack
* CBC Mode Cryptography
* PKCS#7 Padding Standard
