import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Generate key once (note: this will reset every rerun, better to store it persistently in production)
if 'cipher' not in st.session_state:
    KEY = Fernet.generate_key()
    st.session_state.cipher = Fernet(KEY)

# Session state initialization
if "failed_attempts" not in st.session_state:
    st.session_state["failed_attempts"] = 0
if "is_logged_in" not in st.session_state:
    st.session_state["is_logged_in"] = True
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

# Helper functions
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return st.session_state.cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    hashed = hash_passkey(passkey)
    # Check if this encrypted text exists in our storage
    if encrypted_text in st.session_state.stored_data:
        # Check if the passkey matches
        if st.session_state.stored_data[encrypted_text]["passkey"] == hashed:
            try:
                decrypted = st.session_state.cipher.decrypt(encrypted_text.encode()).decode()
                st.session_state["failed_attempts"] = 0
                return decrypted
            except:
                return None
    st.session_state["failed_attempts"] += 1
    return None

# Streamlit UI
st.set_page_config(page_title="Secure Data System", page_icon="🔐")
st.title("🔐 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("📂 Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to Secure Data Platform")
    st.write("Use this app to securely **store** and **retrieve** your confidential data with a passkey.")

elif choice == "Store Data":
    st.subheader("📥 Store Your Data Securely")
    user_data = st.text_area("🔤 Enter Your Secret Data:")
    passkey = st.text_input("🔑 Create a Passkey:", type="password")

    if st.button("🔒 Encrypt & Save"):
        if user_data and passkey:
            hashed = hash_passkey(passkey)
            encrypted = encrypt_data(user_data)
            st.session_state.stored_data[encrypted] = {"passkey": hashed}
            st.success("✅ Data encrypted and saved securely!")
            st.code(f"Encrypted Text:\n{encrypted}", language="text")
            st.info("⚠️ Copy this encrypted text to retrieve your data later")
        else:
            st.warning("⚠️ Both fields are required!")

elif choice == "Retrieve Data":
    if not st.session_state["is_logged_in"] and st.session_state["failed_attempts"] >= 3:
        st.warning("🔒 Too many failed attempts. Redirecting to login...")
        st.rerun()

    st.subheader("🔍 Retrieve Your Data")
    encrypted_input = st.text_area("📄 Paste Encrypted Text Here:")
    input_passkey = st.text_input("🔑 Enter Your Passkey:", type="password")

    if st.button("🔓 Decrypt"):
        if encrypted_input and input_passkey:
            decrypted = decrypt_data(encrypted_input, input_passkey)
            if decrypted is not None:
                st.success("✅ Data Decrypted Successfully:")
                st.code(decrypted, language="text")
            else:
                attempts_left = 3 - st.session_state["failed_attempts"]
                st.error(f"❌ Incorrect passkey or encrypted text! Attempts left: {attempts_left}")
                if st.session_state["failed_attempts"] >= 3:
                    st.session_state["is_logged_in"] = False
                    st.warning("🚫 Too many failed attempts. Please log in again.")
                    st.rerun()
        else:
            st.warning("⚠️ Please provide both encrypted text and passkey.")

elif choice == "Login":
    st.subheader("🔐 Reauthorization Required")
    login_pass = st.text_input("🔑 Enter Master Login Password:", type="password")

    if st.button("🔓 Login"):
        if login_pass == "admin123":
            st.session_state["failed_attempts"] = 0
            st.session_state["is_logged_in"] = True
            st.success("✅ Logged in successfully!")
            st.info("Redirecting to Retrieve Data page...")
            st.rerun()
        else:
            st.error("❌ Incorrect master password!")

st.markdown("---")
st.caption("Developed for Secure Encryption Assignment | Python + Streamlit 🚀")