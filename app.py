import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
import os

# ==============================
# File Encryption & Decryption App
# Stable Version v1.7
# Added: File size display + action confirmation dialogs
# ==============================

root = tk.Tk()
root.title("File Encryption & Decryption App v1.7")
root.geometry("460x500")
root.resizable(False, False)
root.configure(bg="#e8eef3")

status_text = tk.StringVar(value="Status: Ready")
selected_file = tk.StringVar(value="No file selected")
file_info = tk.StringVar(value="")

def set_status(msg):
    status_text.set(f"Status: {msg}")
    root.update_idletasks()

# ==============================
# File Selection
# ==============================

def choose_file():
    path = filedialog.askopenfilename()
    if path:
        selected_file.set(path)

        size = os.path.getsize(path) / 1024
        file_info.set(f"Size: {size:.2f} KB")

        set_status("File selected")

# ==============================
# Key Management
# ==============================

def create_key():
    key = Fernet.generate_key()

    save_path = filedialog.asksaveasfilename(
        title="Save Key File",
        defaultextension=".key",
        filetypes=[("Key Files", "*.key")]
    )

    if not save_path:
        set_status("Key save cancelled")
        return

    with open(save_path, "wb") as f:
        f.write(key)

    messagebox.showinfo("Success", "Key file created")
    set_status("Key generated")

def load_key():
    if os.path.exists("secret.key"):
        with open("secret.key", "rb") as f:
            set_status("Default key loaded")
            return f.read()
    return None

def load_custom_key():
    path = filedialog.askopenfilename(
        title="Select key file",
        filetypes=[("Key Files", "*.key"), ("All Files", "*.*")]
    )
    if not path:
        return None
    try:
        with open(path, "rb") as f:
            key = f.read()
        set_status("Custom key loaded")
        return key
    except Exception:
        messagebox.showerror("Error", "Invalid key file")
        set_status("Key load failed")
        return None

# ==============================
# Encryption
# ==============================

def encrypt_file():
    if not messagebox.askyesno("Confirm", "Encrypt selected file?"):
        return

    key = load_key() or load_custom_key()
    if not key:
        messagebox.showerror("Error", "No key found")
        set_status("Missing key")
        return

    path = selected_file.get()
    if path == "No file selected":
        messagebox.showerror("Error", "Select a file first")
        return

    if path.endswith(".enc"):
        messagebox.showwarning("Warning", "File already encrypted")
        return

    try:
        set_status("Encrypting...")
        f = Fernet(key)

        with open(path, "rb") as file:
            data = file.read()

        encrypted = f.encrypt(data)
        new_path = path + ".enc"

        if os.path.exists(new_path):
            messagebox.showwarning("Warning", "Encrypted file exists")
            return

        with open(new_path, "wb") as file:
            file.write(encrypted)

        messagebox.showinfo("Success", "File encrypted")
        set_status("Encrypted successfully")

    except Exception as e:
        messagebox.showerror("Error", str(e))
        set_status("Encrypt failed")

# ==============================
# Decryption
# ==============================

def decrypt_file():
    if not messagebox.askyesno("Confirm", "Decrypt selected file?"):
        return

    key = load_key() or load_custom_key()
    if not key:
        messagebox.showerror("Error", "No key found")
        set_status("Missing key")
        return

    path = selected_file.get()
    if path == "No file selected":
        messagebox.showerror("Error", "Select a file first")
        return

    try:
        set_status("Decrypting...")
        f = Fernet(key)

        with open(path, "rb") as file:
            data = file.read()

        decrypted = f.decrypt(data)

        new_path = path[:-4] if path.endswith(".enc") else path + ".dec"

        if os.path.exists(new_path):
            messagebox.showwarning("Warning", "Output file exists")
            return

        with open(new_path, "wb") as file:
            file.write(decrypted)

        messagebox.showinfo("Success", "File decrypted")
        set_status("Decrypted successfully")

    except Exception:
        messagebox.showerror("Error", "Wrong key or corrupted file")
        set_status("Decrypt failed")

# ==============================
# GUI
# ==============================

tk.Label(root, text="File Encryption & Decryption v1.7",
         font=("Arial", 16, "bold"),
         bg="#e8eef3").pack(pady=15)

tk.Label(root, text="Secure your files with Fernet encryption",
         font=("Arial", 12),
         bg="#e8eef3").pack()

tk.Button(root, text="Generate Key", width=28,
          command=create_key).pack(pady=8)

tk.Button(root, text="Select File", width=28,
          command=choose_file).pack(pady=8)

tk.Label(root, textvariable=selected_file,
         wraplength=400,
         bg="#e8eef3").pack(pady=5)

tk.Label(root, textvariable=file_info,
         bg="#e8eef3").pack()

tk.Button(root, text="Encrypt File", width=28,
          command=encrypt_file).pack(pady=8)

tk.Button(root, text="Decrypt File", width=28,
          command=decrypt_file).pack(pady=8)

tk.Label(root, textvariable=status_text,
         bg="#e8eef3",
         fg="blue").pack(pady=15)

root.mainloop()








