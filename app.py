import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
import os

# ==============================
# Key Management
# ==============================

def create_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:   # fixed name
        key_file.write(key)
    messagebox.showinfo("Success", "Encryption key created as 'secret.key'")  # moved inside function


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
root.title("File Encryption & Decryption App v1.1")
root.geometry("420x260")
root.resizable(False, False)

label = tk.Label(root, text="File Encryption & Decryption v1.1", font=("Arial", 16, "bold"))
label.pack(pady=20)

btn_key = tk.Button(root, text="Generate Key", width=25, height=2, command=create_key)
btn_key.pack(pady=10)

btn_encrypt = tk.Button(root, text="Encrypt File", width=25, height=2, command=encrypt_file)
btn_encrypt.pack(pady=10)

btn_decrypt = tk.Button(root, text="Decrypt File", width=25, height=2, command=decrypt_file)
btn_decrypt.pack(pady=10)

root.mainloop()
