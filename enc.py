import tkinter as tk
from tkinter import messagebox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Function to encrypt
def encrypt_message():
    try:
        key = key_entry.get().encode()
        plaintext = text_entry.get().encode()
        cipher = AES.new(pad(key, AES.block_size), AES.MODE_ECB)
        encrypted = cipher.encrypt(pad(plaintext, AES.block_size))
        result.delete('1.0', tk.END)
        result.insert(tk.END, encrypted.hex())
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Function to decrypt
def decrypt_message():
    try:
        key = key_entry.get().encode()
        encrypted = bytes.fromhex(text_entry.get())
        cipher = AES.new(pad(key, AES.block_size), AES.MODE_ECB)
        decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
        result.delete('1.0', tk.END)
        result.insert(tk.END, decrypted.decode())
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Create main window
root = tk.Tk()
root.title("AES Encryption/Decryption")

# Create and place widgets
tk.Label(root, text="Key:").grid(row=0, column=0)
key_entry = tk.Entry(root)
key_entry.grid(row=0, column=1)

# tk.Label(root, text="KeyVal:").grid(ro1=0,column=0)
# key_entry = tk.Listbox(root)
# key_entry.grid(row=0, column=1)

tk.Label(root, text="Text:").grid(row=1, column=0)
text_entry = tk.Entry(root)
text_entry.grid(row=1, column=1)

encrypt_button = tk.Button(root, text="Encrypt", command=encrypt_message)
encrypt_button.grid(row=2, column=0)

decrypt_button = tk.Button(root, text="Decrypt", command=decrypt_message)
decrypt_button.grid(row=2, column=1)

result = tk.Text(root, height=10, width=50)
result.grid(row=3, column=0, columnspan=2)

# Run the application
root.mainloop()
