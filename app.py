import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
import os

# ==============================
# File Encryption & Decryption App using Tkinter and Fernet
# Version 1.2 - minor GUI update for commit
# ==============================

# ==============================
# Key Management
# ==============================

def create_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
    messagebox.showinfo("Success", "Encryption key created as 'secret.key'")

def load_key():
    if not os.path.exists("secret.key"):
        messagebox.showerror("Error", "secret.key not found. Generate key first.")
        return None
    return open("secret.key", "rb").read()

# ==============================
# File Encryption
# ==============================

def encrypt_file():
    key = load_key()
    if not key:
        return

    file_path = filedialog.askopenfilename()
    if not file_path:
        return

    try:
        f = Fernet(key)
        with open(file_path, "rb") as file:
            data = file.read()

        encrypted = f.encrypt(data)

        new_path = file_path + ".enc"
        with open(new_path, "wb") as file:
            file.write(encrypted)

        messagebox.showinfo("Success", f"File encrypted:\n{new_path}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# ==============================
# File Decryption
# ==============================

def decrypt_file():
    key = load_key()
    if not key:
        return

    file_path = filedialog.askopenfilename()
    if not file_path:
        return

    try:
        f = Fernet(key)
        with open(file_path, "rb") as file:
            data = file.read()

        decrypted = f.decrypt(data)

        if file_path.endswith(".enc"):
            new_path = file_path[:-4]
        else:
            new_path = file_path + ".dec"

        with open(new_path, "wb") as file:
            file.write(decrypted)

        messagebox.showinfo("Success", f"File decrypted:\n{new_path}")
    except Exception:
        messagebox.showerror("Error", "Invalid key or corrupted file")

# ==============================
# GUI
# ==============================

root = tk.Tk()
root.title("File Encryption & Decryption App v1.2 [Updated]")  # updated for commit
root.geometry("420x320")
root.resizable(False, False)
root.configure(bg="#e8eef3")  # slightly updated background color

# Main title label
label = tk.Label(
    root,
    text="File Encryption & Decryption v1.2",
    font=("Arial", 16, "bold"),
    bg="#e8eef3"
)
label.pack(pady=15)

# Subtitle label
subtitle = tk.Label(
    root,
    text="Securely encrypt and decrypt your files",
    font=("Arial", 12),
    bg="#e8eef3"
)
subtitle.pack(pady=5)

# Buttons
tk.Button(root, text="Generate Key", width=25, command=create_key).pack(pady=10)
tk.Button(root, text="Encrypt File", width=25, command=encrypt_file).pack(pady=10)
tk.Button(root, text="Decrypt File", width=25, command=decrypt_file).pack(pady=10)

# Start GUI
root.mainloop()


