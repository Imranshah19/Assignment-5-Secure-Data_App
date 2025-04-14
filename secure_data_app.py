import streamlit as st
import hashlib, json, os, time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# File path for storing data
DATA_FILE = "users.json"

# Constants
MAX_ATTEMPTS = 3
LOCKOUT_TIME = 60  # seconds
SALT = b'some_random_salt'  # In real apps, use a secure unique salt per user

# Load data from file or initialize
if not os.path.exists(DATA_FILE):
    with open(DATA_FILE, 'w') as f:
        json.dump({}, f)

with open(DATA_FILE, 'r') as f:
    users_data = json.load(f)

# Session state init
if "user" not in st.session_state:
    st.session_state.user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = {}
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = {}

# Helper: Save data to JSON
def save_data():
    with open(DATA_FILE, 'w') as f:
        json.dump(users_data, f, indent=4)

# Helper: Generate encryption key using PBKDF2
def generate_key(password):
    kdf = pbkdf2_hmac('sha256', password.encode(), SALT, 100000)
    return urlsafe_b64encode(kdf)

# Helper: Encrypt/Decrypt
def encrypt_data(text, key):
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, key):
    cipher = Fernet(key)
    return cipher.decrypt(encrypted_text.encode()).decode()

# Authentication
def login(username, password):
    if username in users_data:
        user_info = users_data[username]
        key = generate_key(password)
        if user_info["key"] == key.decode():
            st.session_state.user = username
            st.session_state.password = password  # Store password in session
            return True
    return False

def register(username, password):
    if username not in users_data:
        key = generate_key(password)
        users_data[username] = {
            "key": key.decode(),
            "data": []
        }
        save_data()
        return True
    return False

# UI Starts
st.title("🔐 Secure Multi-User Encryption App")

# Lockout check
def is_locked_out(user):
    if user in st.session_state.lockout_time:
        time_since = time.time() - st.session_state.lockout_time[user]
        if time_since < LOCKOUT_TIME:
            return True, int(LOCKOUT_TIME - time_since)
        else:
            del st.session_state.lockout_time[user]
            st.session_state.failed_attempts[user] = 0
    return False, 0

# Login/Register
if not st.session_state.user:
    auth_choice = st.sidebar.radio("Login/Register", ["Login", "Register"])
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if auth_choice == "Login":
        if st.button("Login"):
            locked, wait_time = is_locked_out(username)
            if locked:
                st.warning(f"⏳ Locked out! Try again in {wait_time} seconds.")
            elif login(username, password):
                st.success(f"✅ Welcome, {username}!")
            else:
                st.session_state.failed_attempts[username] = st.session_state.failed_attempts.get(username, 0) + 1
                if st.session_state.failed_attempts[username] >= MAX_ATTEMPTS:
                    st.session_state.lockout_time[username] = time.time()
                    st.error("🔒 Too many failed attempts. Locked out!")
                else:
                    remaining = MAX_ATTEMPTS - st.session_state.failed_attempts[username]
                    st.error(f"❌ Invalid credentials! Attempts left: {remaining}")
    else:
        if st.button("Register"):
            if register(username, password):
                st.success("✅ Registered! Now log in.")
            else:
                st.warning("⚠️ Username already exists!")

# Main Features
else:
    st.sidebar.success(f"Logged in as: {st.session_state.user}")
    menu = ["Store Data", "Retrieve Data", "Logout"]
    choice = st.sidebar.selectbox("Menu", menu)

    user_key = generate_key(st.session_state.password)  # Use stored password

    if choice == "Store Data":
        st.subheader("📥 Store Data")
        user_input = st.text_area("Enter your secret data:")
        if st.button("Encrypt & Save"):
            if user_input:
                encrypted = encrypt_data(user_input, user_key)
                users_data[st.session_state.user]["data"].append(encrypted)
                save_data()
                st.success("✅ Data saved securely!")
                st.code(encrypted, language="text")
            else:
                st.error("⚠️ Please enter some data!")

    elif choice == "Retrieve Data":
        st.subheader("📤 Your Stored Data")
        encrypted_items = users_data[st.session_state.user]["data"]
        if not encrypted_items:
            st.info("📭 No data stored yet.")
        else:
            for i, item in enumerate(encrypted_items):
                with st.expander(f"Encrypted Data #{i+1}"):
                    st.code(item, language="text")
                    if st.button(f"Decrypt #{i+1}", key=f"decrypt_button_{i}"):
                        try:
                            decrypted = decrypt_data(item, user_key)
                            st.success("🔓 Decrypted:")
                            st.code(decrypted, language="text")
                        except:
                            st.error("❌ Decryption failed. Key mismatch!")

    elif choice == "Logout":
        st.session_state.user = None
        st.session_state.password = None
        st.experimental_rerun()
