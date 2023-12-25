import tkinter as tk
from tkinter import filedialog, ttk, messagebox
from datetime import datetime, timedelta
import os
import base64
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

PREDEFINED_FOLDER = "path/to/predefined/folder"  # Replace with your predefined folder path

# [Certificate Checker and AES Functions remain the same]

# Base64 Encoding/Decoding Functions
def base64_encode():
    input_text = base64_input_entry.get()
    encoded_text = base64.b64encode(input_text.encode()).decode()
    base64_output_text.delete('1.0', tk.END)
    base64_output_text.insert(tk.END, encoded_text)

def base64_decode():
    input_text = base64_input_entry.get()
    try:
        decoded_text = base64.b64decode(input_text).decode()
        base64_output_text.delete('1.0', tk.END)
        base64_output_text.insert(tk.END, decoded_text)
    except Exception as e:
        messagebox.showerror("Decoding Error", str(e))

# Create main window
root = tk.Tk()
root.title("Utility Application")

tab_control = ttk.Notebook(root)

# Certificate Tab
# [Certificate Tab setup remains the same]

# AES Tab
# [AES Tab setup remains the same]

# Base64 Tab
base64_tab = ttk.Frame(tab_control)
tab_control.add(base64_tab, text="Base64 Encode/Decode")

# Base64 Widgets
tk.Label(base64_tab, text="Input Text:").pack()
base64_input_entry = tk.Entry(base64_tab)
base64_input_entry.pack()

encode_button = tk.Button(base64_tab, text="Encode", command=base64_encode)
encode_button.pack()

decode_button = tk.Button(base64_tab, text="Decode", command=base64_decode)
decode_button.pack()

base64_output_text = tk.Text(base64_tab, height=5, width=50)
base64_output_text.pack()

# Finish setup
tab_control.pack(expand=1, fill="both")

# Initial check in predefined folder (for Certificate Tab)
check_certificates(PREDEFINED_FOLDER)

root.mainloop()
