"""
File Encryption & Decryption App
Version: 1.2 (Coursework Updated)
Requires: cryptography
"""

import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet, InvalidToken
import os

# ------------------------
# Window Setup
# ------------------------
root = tk.Tk()
root.title("File Encryption App")
root.geometry("420x370")
root.resizable(False, False)

selected_file = ""
current_key = None
overwrite = tk.BooleanVar()
status = tk.StringVar(value="Ready")
file_label = tk.StringVar(value="No file selected")

# ------------------------
# Helper Functions
# ------------------------
def update_status(msg):
    status.set(msg)

def save_file_with_check(path):
    """Automatically appends _new if file exists and overwrite not checked"""
    if os.path.exists(path) and not overwrite.get():
        base, ext = os.path.splitext(path)
        path = f"{base}_new{ext}"
    return path

# ------------------------
# Key Functions
# ------------------------
def generate_key():
    global current_key
    try:
        key = Fernet.generate_key()
        path = filedialog.asksaveasfilename(defaultextension=".key",
                                            filetypes=[("Key Files", "*.key")])
        if path:
            with open(path, "wb") as f:
                f.write(key)
            current_key = key
            update_status("Key generated successfully")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def load_key():
    global current_key
    try:
        path = filedialog.askopenfilename(filetypes=[("Key Files", "*.key")])
        if path:
            with open(path, "rb") as f:
                current_key = f.read()
            update_status("Key loaded successfully")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# ------------------------
# File Selection
# ------------------------
def choose_file():
    global selected_file
    path = filedialog.askopenfilename()
    if path:
        selected_file = path 
        file_label.set(os.path.basename(path))
        update_status("File selected")

# ------------------------
# Encryption & Decryption
# ------------------------
def encrypt():
    if not current_key or not selected_file:
        messagebox.showerror("Error", "Select file and load/generate key first")
        return
    try:
        f = Fernet(current_key)
        with open(selected_file, "rb") as file:
            data = file.read()
        new_path = save_file_with_check(selected_file + ".enc")
        with open(new_path, "wb") as file:
            file.write(f.encrypt(data))
        update_status(f"Encrypted: {os.path.basename(new_path)}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def decrypt():
    if not current_key or not selected_file:
        messagebox.showerror("Error", "Select file and load/generate key first")
        return
    if not selected_file.endswith(".enc"):
        messagebox.showerror("Error", "Select a .enc file to decrypt")
        return
    try:
        f = Fernet(current_key)
        with open(selected_file, "rb") as file:
            data = file.read()
        new_path = save_file_with_check(selected_file.replace(".enc", ".dec"))
        with open(new_path, "wb") as file:
            file.write(f.decrypt(data))
        update_status(f"Decrypted: {os.path.basename(new_path)}")
    except InvalidToken:
        messagebox.showerror("Error", "Wrong key or corrupted file")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# ------------------------
# UI Setup
# ------------------------
tk.Label(root, text="File Encryption & Decryption", font=("Arial", 14, "bold")).pack(pady=10)

def create_button(text, cmd):
    tk.Button(root, text=text, width=25, command=cmd).pack(pady=4)

create_button("Generate Key", generate_key)
create_button("Load Key", load_key)
create_button("Select File", choose_file)
tk.Label(root, textvariable=file_label, wraplength=380).pack()
tk.Checkbutton(root, text="Overwrite output file", variable=overwrite).pack(pady=6)
create_button("Encrypt", encrypt)
create_button("Decrypt", decrypt)
tk.Label(root, textvariable=status).pack(pady=10)

root.mainloop()