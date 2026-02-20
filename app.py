import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
import os

# ==============================
# File Encryption & Decryption App v1.11
# Added: smart size display + key status color + operation counter
# ==============================

root = tk.Tk()
root.title("File Encryption & Decryption App v1.11")
root.geometry("500x620")
root.resizable(False, False)
root.configure(bg="#e8eef3")

status_text = tk.StringVar(value="Status: Ready")
selected_file = tk.StringVar(value="No file selected")
file_info = tk.StringVar(value="")
file_type = tk.StringVar(value="")
key_path_var = tk.StringVar(value="No key selected")
output_folder = tk.StringVar(value="No folder selected")
overwrite_var = tk.BooleanVar(value=False)
op_count_var = tk.StringVar(value="Operations: 0")

current_key = None
operation_count = 0

def set_status(msg):
    status_text.set(f"Status: {msg}")
    root.update_idletasks()

def inc_ops():
    global operation_count
    operation_count += 1
    op_count_var.set(f"Operations: {operation_count}")

# ==============================
# File Selection
# ==============================

def choose_file():
    path = filedialog.askopenfilename()
    if path:
        selected_file.set(path)

        size_kb = os.path.getsize(path) / 1024
        if size_kb > 1024:
            file_info.set(f"Size: {size_kb/1024:.2f} MB")
        else:
            file_info.set(f"Size: {size_kb:.2f} KB")

        ext = os.path.splitext(path)[1] or "No extension"
        file_type.set(f"Type: {ext}")
        set_status("File selected")

def clear_file():
    selected_file.set("No file selected")
    file_info.set("")
    file_type.set("")
    set_status("Selection cleared")

def choose_folder():
    path = filedialog.askdirectory()
    if path:
        output_folder.set(path)
        set_status("Output folder selected")

# ==============================
# Key Management
# ==============================

def create_key():
    global current_key
    key = Fernet.generate_key()
    save_path = filedialog.asksaveasfilename(defaultextension=".key",
                                             filetypes=[("Key Files", "*.key")])
    if not save_path:
        return
    with open(save_path, "wb") as f:
        f.write(key)
    current_key = key
    key_path_var.set(save_path)
    key_label.config(fg="green")
    messagebox.showinfo("Success", "Key created and loaded")
    set_status("Key generated")

def load_key_file():
    global current_key
    path = filedialog.askopenfilename(filetypes=[("Key Files", "*.key")])
    if not path:
        return
    try:
        with open(path, "rb") as f:
            current_key = f.read()
        key_path_var.set(path)
        key_label.config(fg="green")
        set_status("Key loaded")
    except:
        key_label.config(fg="red")
        messagebox.showerror("Error", "Invalid key file")

# ==============================
# Encryption
# ==============================

def encrypt_file():
    if not current_key:
        messagebox.showerror("Error", "Load or create a key first")
        return

    path = selected_file.get()
    if path == "No file selected":
        messagebox.showerror("Error", "Select a file first")
        return

    folder = output_folder.get() if output_folder.get() != "No folder selected" else os.path.dirname(path)
    filename = os.path.basename(path)
    new_path = os.path.join(folder, filename + ".enc")

    if os.path.exists(new_path) and not overwrite_var.get():
        base, ext = os.path.splitext(new_path)
        new_path = base + "_new" + ext

    try:
        set_status("Encrypting...")
        f = Fernet(current_key)

        with open(path, "rb") as file:
            data = file.read()

        encrypted = f.encrypt(data)

        os.makedirs(folder, exist_ok=True)
        with open(new_path, "wb") as file:
            file.write(encrypted)

        inc_ops()
        messagebox.showinfo("Success", f"Encrypted:\n{new_path}")
        set_status("Encryption complete")

    except Exception as e:
        messagebox.showerror("Error", str(e))
        set_status("Encrypt failed")

# ==============================
# Decryption
# ==============================

def decrypt_file():
    if not current_key:
        messagebox.showerror("Error", "Load or create a key first")
        return

    path = selected_file.get()
    if path == "No file selected":
        messagebox.showerror("Error", "Select a file first")
        return

    folder = output_folder.get() if output_folder.get() != "No folder selected" else os.path.dirname(path)
    filename = os.path.basename(path)
    new_path = os.path.join(folder, filename[:-4] if filename.endswith(".enc") else filename + ".dec")

    if os.path.exists(new_path) and not overwrite_var.get():
        base, ext = os.path.splitext(new_path)
        new_path = base + "_new" + ext

    try:
        set_status("Decrypting...")
        f = Fernet(current_key)

        with open(path, "rb") as file:
            data = file.read()

        decrypted = f.decrypt(data)

        os.makedirs(folder, exist_ok=True)
        with open(new_path, "wb") as file:
            file.write(decrypted)

        inc_ops()
        messagebox.showinfo("Success", f"Decrypted:\n{new_path}")
        set_status("Decryption complete")

    except Exception:
        messagebox.showerror("Error", "Wrong key or corrupted file")
        set_status("Decrypt failed")

# ==============================
# GUI
# ==============================

tk.Label(root, text="File Encryption & Decryption v1.11",
         font=("Arial", 16, "bold"),
         bg="#e8eef3").pack(pady=12)

tk.Button(root, text="Generate Key", width=32, command=create_key).pack(pady=5)
tk.Button(root, text="Load Key File", width=32, command=load_key_file).pack(pady=5)

key_label = tk.Label(root, textvariable=key_path_var,
                     wraplength=440, bg="#e8eef3", fg="red")
key_label.pack(pady=4)

tk.Button(root, text="Select File", width=32, command=choose_file).pack(pady=5)
tk.Button(root, text="Clear Selection", width=32, command=clear_file).pack(pady=3)

tk.Label(root, textvariable=selected_file, wraplength=440, bg="#e8eef3").pack()
tk.Label(root, textvariable=file_info, bg="#e8eef3").pack()
tk.Label(root, textvariable=file_type, bg="#e8eef3").pack()

tk.Button(root, text="Select Output Folder", width=32, command=choose_folder).pack(pady=5)
tk.Label(root, textvariable=output_folder, wraplength=440, bg="#e8eef3").pack(pady=4)

tk.Checkbutton(root, text="Allow overwrite output file",
               variable=overwrite_var, bg="#e8eef3").pack(pady=6)

tk.Button(root, text="Encrypt File", width=32, command=encrypt_file).pack(pady=6)
tk.Button(root, text="Decrypt File", width=32, command=decrypt_file).pack(pady=6)

tk.Label(root, textvariable=op_count_var, bg="#e8eef3").pack()

tk.Label(root, textvariable=status_text,
         bg="#e8eef3", fg="blue").pack(pady=12)

root.mainloop()











