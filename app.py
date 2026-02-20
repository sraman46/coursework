"""
Simple File Encryption & Decryption App
Version: 1.0 (Coursework)
Requires: cryptography
"""

import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet, InvalidToken
import os

# ------------------------
# Window
# ------------------------

root = tk.Tk()
root.title("File Encryption App")
root.geometry("420x360")

selected_file = ""
current_key = None
overwrite = tk.BooleanVar()

# ------------------------
# Key Functions
# ------------------------

def generate_key():
    global current_key
    key = Fernet.generate_key()
    path = filedialog.asksaveasfilename(defaultextension=".key")
    if path:
        with open(path, "wb") as f:
            f.write(key)
        current_key = key
        status.set("Key generated")


def load_key():
    global current_key
    path = filedialog.askopenfilename(filetypes=[("Key Files","*.key")])
    if path:
        with open(path, "rb") as f:
            current_key = f.read()
        status.set("Key loaded")

# ------------------------
# File Select
# ------------------------

def choose_file():
    global selected_file
    selected_file = filedialog.askopenfilename()
    file_label.set(selected_file if selected_file else "No file selected")

# ------------------------
# Encrypt
# ------------------------

def encrypt():
    if not current_key or not selected_file:
        messagebox.showerror("Error", "Select file and key first")
        return

    f = Fernet(current_key)

    with open(selected_file, "rb") as file:
        data = file.read()

    new_path = selected_file + ".enc"
    if os.path.exists(new_path) and not overwrite.get():
        new_path = selected_file + "_new.enc"

    with open(new_path, "wb") as file:
        file.write(f.encrypt(data))

    status.set("Encrypted")

# ------------------------
# Decrypt
# ------------------------

def decrypt():
    if not current_key or not selected_file:
        messagebox.showerror("Error", "Select file and key first")
        return

    f = Fernet(current_key)

    try:
        with open(selected_file, "rb") as file:
            data = file.read()

        new_path = selected_file.replace(".enc","") + ".dec"
        if os.path.exists(new_path) and not overwrite.get():
            new_path = new_path.replace(".dec","_new.dec")

        with open(new_path, "wb") as file:
            file.write(f.decrypt(data))

        status.set("Decrypted")

    except InvalidToken:
        messagebox.showerror("Error","Wrong key or file")

# ------------------------
# UI
# ------------------------

tk.Label(root, text="File Encryption & Decryption",
         font=("Arial",14,"bold")).pack(pady=10)

tk.Button(root, text="Generate Key", width=25, command=generate_key).pack(pady=4)
tk.Button(root, text="Load Key", width=25, command=load_key).pack(pady=4)

tk.Button(root, text="Select File", width=25, command=choose_file).pack(pady=6)

file_label = tk.StringVar(value="No file selected")
tk.Label(root, textvariable=file_label, wraplength=380).pack()

tk.Checkbutton(root, text="Overwrite output", variable=overwrite).pack(pady=6)

tk.Button(root, text="Encrypt", width=25, command=encrypt).pack(pady=5)
tk.Button(root, text="Decrypt", width=25, command=decrypt).pack(pady=5)

status = tk.StringVar(value="Ready")
tk.Label(root, textvariable=status).pack(pady=10)

root.mainloop()