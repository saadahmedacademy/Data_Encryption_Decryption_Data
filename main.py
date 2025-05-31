import streamlit as st
import os
import base64
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import hashlib

# ------------------- UTILITY FUNCTIONS -------------------

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def derive_key(passkey: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(passkey.encode()))

def encrypt_data(cipher, text: str) -> str:
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(cipher, encrypted_text: str) -> str:
    return cipher.decrypt(encrypted_text.encode()).decode()

# ------------------- FILES -------------------

MASTER_FILE = "master_data.json"
SALT_FILE = "encryption_salt.bin"

# ------------------- SESSION INIT -------------------

if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

if "login_password_hash" not in st.session_state:
    st.session_state.login_password_hash = None

if "is_logged_in" not in st.session_state:
    st.session_state.is_logged_in = False

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "encryption_cipher" not in st.session_state:
    st.session_state.encryption_cipher = None

if "encryption_salt" not in st.session_state:
    if os.path.exists(SALT_FILE):
        with open(SALT_FILE, "rb") as f:
            st.session_state.encryption_salt = f.read()
    else:
        salt = os.urandom(16)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
        st.session_state.encryption_salt = salt

# ------------------- LOGIN / SIGNUP -------------------

def set_login_password():
    st.title("🔐 Set Master Password")
    pass1 = st.text_input("Set Password", type="password")
    pass2 = st.text_input("Confirm Password", type="password")

    if st.button("Save Password"):
        if len(pass1) < 8:
            st.error("Password must be at least 8 characters long.")
        elif pass1 != pass2:
            st.error("Passwords do not match.")
        else:
            password_hash = hash_passkey(pass1)
            with open(MASTER_FILE, "w") as f:
                json.dump({"password_hash": password_hash}, f)

            st.session_state.login_password_hash = password_hash
            key = derive_key(pass1, st.session_state.encryption_salt)
            st.session_state.encryption_cipher = Fernet(key)
            st.success("Master password set! Please log in.")
            st.rerun()

def login_page():
    st.title("🔑 Login")
    input_pass = st.text_input("Enter Master Password", type="password")

    if st.button("Login"):
        password_hash = hash_passkey(input_pass)

        if password_hash == st.session_state.login_password_hash:
            key = derive_key(input_pass, st.session_state.encryption_salt)
            st.session_state.encryption_cipher = Fernet(key)
            st.session_state.is_logged_in = True
            st.session_state.failed_attempts = 0
            st.success("✅ Login successful!")
            st.rerun()
        else:
            st.session_state.failed_attempts += 1
            st.error(f"❌ Incorrect password! Attempts left: {3 - st.session_state.failed_attempts}")
            if st.session_state.failed_attempts >= 3:
                st.warning("🔒 Too many failed attempts. App locked.")
                st.stop()

# ------------------- MAIN APP -------------------

def main_app():
    st.title("🔒 Secure Data Encryption App")

    menu = ["Home", "Store Data", "Retrieve Data"]
    choice = st.sidebar.selectbox("Navigation", menu)

    if choice == "Home":
        st.subheader("🏠 Welcome")
        st.write("Store and retrieve data securely.")
        if st.session_state.stored_data:
            st.write("📦 Stored Titles:")
            st.write(list(st.session_state.stored_data.keys()))

    elif choice == "Store Data":
        st.subheader("📥 Store Data")
        title = st.text_input("Enter Title")
        text = st.text_area("Enter Data")

        if st.button("Encrypt & Save"):
            if not title or not text:
                st.error("All fields required!")
            elif title in st.session_state.stored_data:
                st.warning("Title already exists!")
            else:
                encrypted = encrypt_data(st.session_state.encryption_cipher, text)
                st.session_state.stored_data[title] = encrypted
                st.success("✅ Data stored securely.")

    elif choice == "Retrieve Data":
        st.subheader("🔍 Retrieve Data")
        title = st.text_input("Enter Title to Retrieve")

        if st.button("Decrypt"):
            if title in st.session_state.stored_data:
                try:
                    decrypted = decrypt_data(st.session_state.encryption_cipher, st.session_state.stored_data[title])
                    st.success(f"✅ Decrypted Data: {decrypted}")
                except:
                    st.error("❌ Decryption failed. Invalid key or corrupted data.")
            else:
                st.error("Title not found.")

# ------------------- CONTROLLER -------------------

if os.path.exists(MASTER_FILE):
    with open(MASTER_FILE, "r") as f:
        st.session_state.login_password_hash = json.load(f)["password_hash"]

if st.session_state.login_password_hash is None:
    set_login_password()
elif not st.session_state.is_logged_in:
    login_page()
else:
    main_app()
