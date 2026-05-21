import os
import hashlib
from datetime import datetime
import streamlit as st
from cryptography.fernet import Fernet

# -----------------------------
# Folders
# -----------------------------
UPLOAD_FOLDER = "uploads"
ENCRYPTED_FOLDER = "encrypted"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)

# -----------------------------
# Sensitive Keywords
# -----------------------------
SENSITIVE_KEYWORDS = [
    "confidential",
    "secret",
    "restricted",
    "finance"
]

# -----------------------------
# Encryption Key
# -----------------------------
if not os.path.exists("secret.key"):

    key = Fernet.generate_key()

    with open("secret.key", "wb") as f:
        f.write(key)

with open("secret.key", "rb") as f:
    key = f.read()

cipher = Fernet(key)

# -----------------------------
# Helper Functions
# -----------------------------
def generate_hashes(data):

    sha256 = hashlib.sha256(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()

    return sha256, md5


def is_sensitive(filename):

    return any(
        keyword.lower() in filename.lower()
        for keyword in SENSITIVE_KEYWORDS
    )

# -----------------------------
# Streamlit UI
# -----------------------------
st.title("Secure File Transfer System")

st.write("Upload and encrypt files securely.")

uploaded_file = st.file_uploader("Choose a file")

if uploaded_file is not None:

    file_data = uploaded_file.read()

    sha256, md5 = generate_hashes(file_data)

    encrypted_data = cipher.encrypt(file_data)

    encrypted_path = os.path.join(
        ENCRYPTED_FOLDER,
        uploaded_file.name + ".enc"
    )

    with open(encrypted_path, "wb") as f:
        f.write(encrypted_data)

    st.success("File encrypted and saved successfully")

    st.write("### File Information")
    st.write("Filename:", uploaded_file.name)
    st.write("SHA256:", sha256)
    st.write("MD5:", md5)

    if is_sensitive(uploaded_file.name):
        st.error("Sensitive file detected")

# -----------------------------
# Download Section
# -----------------------------
st.write("## Download Encrypted Files")

files = os.listdir(ENCRYPTED_FOLDER)

for file in files:

    file_path = os.path.join(ENCRYPTED_FOLDER, file)

    with open(file_path, "rb") as f:
        encrypted_data = f.read()

    decrypted_data = cipher.decrypt(encrypted_data)

    st.download_button(
        label=f"Download {file}",
        data=decrypted_data,
        file_name=file.replace(".enc", "")
    )

st.write("System running successfully")
