import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
import os

# ==============================
# File Encryption & Decryption App using Tkinter and Fernet
# Version 1.3 - status label + safer file handling
# ==============================

status_text = None

# ==============================
# Key Management
# ==============================

def set_status(msg):
    status_text.set(f"Status: {msg}")

def create_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
    messagebox.showinfo("Success", "Encryption key created as 'secret.key'")
    set_status("Key generated")

def load_key():
    if not os.path.exists("secret.key"):
        messagebox.showerror("Error", "secret.key not found. Generate key first.")
        set_status("Missing key")
        return None
    return open("secret.key", "rb").read()

# ==============================
# File Encryption
# ==============================

def encrypt_file():
    key = load_key()
    if not key:
        return

    file_path = filedialog.askopenfilename(
        title="Select file to encrypt",
        filetypes=[("All Files", "*.*")]
    )
    if not file_path:
        return

    try:
        f = Fernet(key)
        with open(file_path, "rb") as file:
            data = file.read()

        encrypted = f.encrypt(data)

        new_path = file_path + ".enc"
        if os.path.exists(new_path):
            messagebox.showwarning("Warning", "Encrypted file already exists")
            set_status("Encrypt skipped (exists)")
            return

        with open(new_path, "wb") as file:
            file.write(encrypted)

        messagebox.showinfo("Success", f"File encrypted:\n{new_path}")
        set_status("File encrypted")

    except Exception as e:
        messagebox.showerror("Error", str(e))
        set_status("Encryption failed")

# ==============================
# File Decryption
# ==============================

def decrypt_file():
    key = load_key()
    if not key:
        return

    file_path = filedialog.askopenfilename(
        title="Select file to decrypt",
        filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")]
    )
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

        if os.path.exists(new_path):
            messagebox.showwarning("Warning", "Output file already exists")
            set_status("Decrypt skipped (exists)")
            return

        with open(new_path, "wb") as file:
            file.write(decrypted)

        messagebox.showinfo("Success", f"File decrypted:\n{new_path}")
        set_status("File decrypted")

    except Exception:
        messagebox.showerror("Error", "Invalid key or corrupted file")
        set_status("Decryption failed")

# ==============================
# GUI
# ==============================

root = tk.Tk()
root.title("File Encryption & Decryption App v1.3")
root.geometry("420x350")
root.resizable(False, False)
root.configure(bg="#e8eef3")

label = tk.Label(
    root,
    text="File Encryption & Decryption v1.3",
    font=("Arial", 16, "bold"),
    bg="#e8eef3"
)
label.pack(pady=15)

subtitle = tk.Label(
    root,
    text="Securely encrypt and decrypt your files",
    font=("Arial", 12),
    bg="#e8eef3"
)
subtitle.pack(pady=5)

tk.Button(root, text="Generate Key", width=25, command=create_key).pack(pady=10)
tk.Button(root, text="Encrypt File", width=25, command=encrypt_file).pack(pady=10)
tk.Button(root, text="Decrypt File", width=25, command=decrypt_file).pack(pady=10)

# NEW: status label (commit-worthy change)
status_text = tk.StringVar()
status_text.set("Status: Ready")
status_label = tk.Label(root, textvariable=status_text, bg="#e8eef3", font=("Arial", 10))
status_label.pack(pady=15)

root.mainloop()



