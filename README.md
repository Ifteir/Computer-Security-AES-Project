# Computer Security AES Project

## Overview

This repository contains a **Computer Security project** based on the implementation of the **AES-128 Encryption and Decryption System** using Python. AES, also known as the Advanced Encryption Standard, is one of the most widely used symmetric key encryption algorithms for protecting sensitive data.

This project demonstrates how plaintext can be encrypted into ciphertext and how ciphertext can be decrypted back into the original plaintext using AES-128. The project is designed for academic learning and practical understanding of cryptography concepts in computer security.

## Project Title

**AES-128 Encryption and Decryption System**

## Subject

**Computer Security**

## Author

**Ifteir Hossain**  
Department of Computer Science and Engineering  
United International University  
Batch: 223

## Project Objectives

The main objectives of this project are:

- To implement AES-128 encryption using Python.
- To implement AES-128 decryption using Python.
- To understand symmetric key cryptography.
- To demonstrate the working process of the AES algorithm.
- To show how plaintext is converted into ciphertext.
- To recover original plaintext from ciphertext through decryption.
- To improve practical knowledge of computer security and cryptographic systems.

## About AES

The **Advanced Encryption Standard (AES)** is a symmetric encryption algorithm used to secure digital data. In symmetric encryption, the same secret key is used for both encryption and decryption.

AES-128 uses a 128-bit key and performs multiple transformation rounds to convert readable plaintext into unreadable ciphertext. It is widely used in secure communication, file protection, database encryption, wireless security, and many modern cybersecurity systems.

## AES-128 Characteristics

AES-128 includes:

- 128-bit block size
- 128-bit key size
- 10 encryption rounds
- Symmetric key encryption
- Substitution and permutation operations
- Strong resistance against brute-force attacks

## Features

- AES-128 encryption implementation
- AES-128 decryption implementation
- Python-based cryptography project
- Demonstrates encryption and decryption workflow
- Includes project report/paper
- Suitable for Computer Security coursework
- Educational implementation for learning AES algorithm

## Project Structure

```text
Computer-Security-AES-Project/
│
├── AES.py
├── AESdecryption.py
├── AES_128_Encryption___Decryption_System.pdf
└── README.md
```

## Files Description

| File Name | Description |
|---|---|
| `AES.py` | Python program for AES-128 encryption |
| `AESdecryption.py` | Python program for AES-128 decryption |
| `AES_128_Encryption___Decryption_System.pdf` | Project report/paper explaining the AES system |
| `README.md` | Documentation file for the GitHub repository |

## Technologies Used

- Python
- AES-128 Algorithm
- Cryptography
- Symmetric Key Encryption
- Computer Security Concepts

## AES Encryption Process

The AES encryption process converts plaintext into ciphertext through several transformation steps.

The main steps are:

1. **AddRoundKey**  
   The plaintext block is combined with the secret key.

2. **SubBytes**  
   Each byte is substituted using a fixed substitution table.

3. **ShiftRows**  
   Rows of the state matrix are shifted to provide diffusion.

4. **MixColumns**  
   Columns of the state matrix are mixed to increase security.

5. **Final Round**  
   The final transformation is applied without the MixColumns step.

After these steps, the original plaintext is converted into encrypted ciphertext.

## AES Decryption Process

The AES decryption process reverses the encryption operations and converts ciphertext back into plaintext.

The main inverse steps are:

1. **Inverse ShiftRows**
2. **Inverse SubBytes**
3. **AddRoundKey**
4. **Inverse MixColumns**

By applying these inverse operations in the correct order, the original message can be recovered from the encrypted ciphertext.

## How to Run the Project

### Step 1: Clone the Repository

```bash
git clone https://github.com/Ifteir/Computer-Security-AES-Project.git
```

### Step 2: Open the Project Folder

```bash
cd Computer-Security-AES-Project
```

### Step 3: Run the Encryption Program

```bash
python AES.py
```

### Step 4: Run the Decryption Program

```bash
python AESdecryption.py
```

## Project Report

The full project report is included in this repository:

```text
AES_128_Encryption___Decryption_System.pdf
```

The report contains the project explanation, methodology, AES algorithm details, implementation process, and conclusion.

## Applications of AES

AES is used in many real-world security systems, such as:

- Secure file encryption
- Online banking systems
- Password protection
- Wireless network security
- VPN encryption
- Secure messaging systems
- Database encryption
- Cloud data security
- Digital communication protection

## Learning Outcomes

After completing this project, the following concepts can be understood:

- Basics of cryptography
- Symmetric key encryption
- AES-128 algorithm structure
- Encryption and decryption process
- Importance of secure key management
- Practical implementation of computer security algorithms using Python

## Conclusion

This project successfully demonstrates the implementation of the AES-128 encryption and decryption system using Python. It provides a practical understanding of how symmetric encryption works and how data can be protected through cryptographic techniques.

The project is useful for students and beginners who want to learn about cryptography, AES, and computer security through hands-on implementation.

## Acknowledgement

This project was completed as part of the **Computer Security** course under the Department of Computer Science and Engineering at **United International University**.

## License

This project is created for academic and educational purposes.
