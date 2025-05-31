# 🔐 Streamlit Secure Data Vault

A simple but secure Streamlit-based application to **encrypt and store sensitive data** using a master password. All encryption is performed using industry-standard libraries, and keys are derived using PBKDF2 with SHA-256.

## ✨ Features

- ✅ Set a **master password** to protect your data
- 🔑 Key derivation using **PBKDF2 + SHA-256**
- 🔐 Data encryption with **Fernet symmetric encryption**
- 🔒 Secure storage of encrypted data in memory (optionally extendable to file/db)
- 🚫 Master key or derived key is **never saved directly**
- 🧂 Salt is randomly generated and stored safely

## 🧠 Technologies Used

- [Streamlit](https://streamlit.io/) — Web app framework
- [cryptography](https://cryptography.io/en/latest/) — Secure key derivation and encryption
- Python standard libraries (`hashlib`, `os`, `base64`, `json`)
- Live Link : https://dataencryptiondecryptiondata-saadahmedacademy.streamlit.app/

## 🚀 Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/streamlit-secure-data-vault.git
cd streamlit-secure-data-vault
2. Create a Virtual Environment
bash
Copy
Edit
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
3. Install Dependencies
bash
Copy
Edit
pip install -r requirements.txt
Make sure requirements.txt includes:

nginx
Copy
Edit
streamlit
cryptography
4. Run the App
bash
Copy
Edit
streamlit run main.py
📂 File Structure
python
Copy
Edit
.
├── main.py                # Main Streamlit application
├── master_data.json       # Stores hashed master password
├── encryption_salt.bin    # Stores the generated salt (secure)
├── README.md              # You're here!
🛡 Security Notes
The app never stores the master password or encryption key.

All encryption/decryption is done in-memory using a Fernet cipher.

The salt is stored to ensure password-derived keys can be consistently regenerated.

📌 Future Improvements
Store encrypted data persistently in a file or database

Add multi-user support

Add password reset using security questions

🧑‍💻 Author — @SaadAhmedAcademy
