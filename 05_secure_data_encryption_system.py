import streamlit as st  
import json  
import os  
from cryptography.fernet import Fernet  
import bcrypt  

# Constants  
DATA_FILE = "secure_data.json"  

# Load data from JSON file  
def load_data():  
    if os.path.exists(DATA_FILE):  
        with open(DATA_FILE, 'r') as file:  
            try:  
                return json.load(file)  
            except json.JSONDecodeError:  
                st.warning("Data file is empty or corrupted. Initializing with empty data.")  
                return {}  
    return {}  

# Save data to JSON file  
def save_data(data):  
    with open(DATA_FILE, 'w') as file:  
        json.dump(data, file)  

# Generate a Fernet key  
def generate_key():  
    return Fernet.generate_key().decode()  

# Encrypt the data  
def encrypt_data(key, data):  
    fernet = Fernet(key.encode())  
    return fernet.encrypt(data.encode()).decode()  

# Decrypt the data  
def decrypt_data(key, encrypted_data):  
    fernet = Fernet(key.encode())  
    return fernet.decrypt(encrypted_data.encode()).decode()  

# Hash the passkey  
def hash_passkey(passkey):  
    return bcrypt.hashpw(passkey.encode(), bcrypt.gensalt()).decode()  

# Verify the hashed passkey  
def verify_passkey(passkey, hashed):  
    return bcrypt.checkpw(passkey.encode(), hashed.encode())  

# Initialize stored data  
stored_data = load_data()  

# Session State for Attempt Count  
if 'attempt_count' not in st.session_state:  
    st.session_state.attempt_count = 0  

def main_page():  
    st.header("🔒Secure Data Encryption System")  
    action = st.selectbox("Select an action", ["Store Data", "Retrieve Data"])  

    if action == "Store Data":  
        store_data_page()  
    elif action == "Retrieve Data":  
        retrieve_data_page()  

def store_data_page():  
    st.subheader("Insert Data")  
    username = st.text_input("Enter your username")  
    text = st.text_area("Enter the text to store")  
    passkey = st.text_input("🔑Enter your passkey", type="password")  

    if st.button("Store"):  
        if username and text and passkey:  
            key = generate_key()  
            encrypted_text = encrypt_data(key, text)  
            stored_data[username] = {  
                "encrypted_text": encrypted_text,  
                "passkey": hash_passkey(passkey),  
                "fernet_key": key  # Store the Fernet key  
            }  
            save_data(stored_data)  
            st.success("✅Data stored successfully!")  
        else:  
            st.error("Please fill in all fields.") 

def retrieve_data_page():  
    st.subheader("Retrieve Data")  
    username = st.text_input("Enter your username for retrieval")  
    passkey = st.text_input("Enter your passkey", type="password")  

    if st.button("Retrieve"):  
        user_data = stored_data.get(username)  
        if user_data:  
            if verify_passkey(passkey, user_data["passkey"]):  
                # Use the stored Fernet key for decryption  
                decrypted_text = decrypt_data(user_data["fernet_key"], user_data["encrypted_text"])  
                st.success(f"Retrieved Data: {decrypted_text}")  
                st.session_state.attempt_count = 0  # Reset attempts  
            else:  
                st.session_state.attempt_count += 1  
                st.error("Invalid passkey!")  
                if st.session_state.attempt_count >= 3:  
                    st.warning("Maximum attempts reached. Redirecting to main page...")  
                    st.session_state.attempt_count = 0  # Reset attempts  
                    main_page()  

# Run main interface  
main_page()  