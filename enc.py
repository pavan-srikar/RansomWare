import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import secrets

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

# Encrypt function for a single file
def encrypt_file(filepath, password):
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

    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed for {filepath}: {str(e)}")

# Decrypt function for a single file
def decrypt_file(filepath, password):
    try:
        with open(filepath, 'rb') as f:
            file_data = f.read()

        salt = file_data[:16]  # First 16 bytes are the salt
        iv = file_data[16:32]  # Next 16 bytes are the IV
        encrypted_data = file_data[32:]

        key = derive_key(password, salt)

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Save decrypted file
        new_filepath = filepath.replace(".enc", "")
        with open(new_filepath, 'wb') as f:
            f.write(decrypted_data)

        # Optionally, remove the encrypted file after decryption
        os.remove(filepath)

    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed for {filepath}: {str(e)}")

# Recursive encryption of files in a folder
def encrypt_folder(folder_path, password):
    for root, _, files in os.walk(folder_path):
        for file in files:
            filepath = os.path.join(root, file)
            encrypt_file(filepath, password)
    messagebox.showinfo("Success", "Folder and files encrypted successfully!")

# Recursive decryption of files in a folder
def decrypt_folder(folder_path, password):
    for root, _, files in os.walk(folder_path):
        for file in files:
            if file.endswith(".enc"):
                filepath = os.path.join(root, file)
                decrypt_file(filepath, password)
    messagebox.showinfo("Success", "Folder and files decrypted successfully!")

# Function to handle both files and folders
def encrypt(filepath, password):
    if os.path.isdir(filepath):
        encrypt_folder(filepath, password)
    else:
        encrypt_file(filepath, password)

def decrypt(filepath, password):
    if os.path.isdir(filepath):
        decrypt_folder(filepath, password)
    else:
        decrypt_file(filepath, password)

# Function to browse for a file or folder
def browse_path():
    path = filedialog.askdirectory() or filedialog.askopenfilename()  # Ask for directory or file
    if path:
        entry_path.delete(0, tk.END)
        entry_path.insert(0, path)

# Main GUI function
def main_gui():
    global entry_path

    window = tk.Tk()
    window.title("Encrypt/Decrypt Files and Folders")
    window.geometry('400x200')

    label_file = tk.Label(window, text="Select File/Folder:")
    label_file.pack(pady=5)
    
    entry_path = tk.Entry(window, width=50)
    entry_path.pack(pady=5)
    
    button_browse = tk.Button(window, text="Browse", command=browse_path)
    button_browse.pack(pady=5)

    label_password = tk.Label(window, text="Enter Password (any length):")
    label_password.pack(pady=5)

    entry_password = tk.Entry(window, show="*", width=20)
    entry_password.pack(pady=5)

    # Encrypt button
    button_encrypt = tk.Button(window, text="Encrypt", command=lambda: encrypt(entry_path.get(), entry_password.get()))
    button_encrypt.pack(pady=5)

    # Decrypt button
    button_decrypt = tk.Button(window, text="Decrypt", command=lambda: decrypt(entry_path.get(), entry_password.get()))
    button_decrypt.pack(pady=5)

    window.mainloop()

if __name__ == "__main__":
    main_gui()
