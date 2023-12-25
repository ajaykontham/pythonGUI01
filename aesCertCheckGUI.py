import tkinter as tk
from tkinter import filedialog, ttk, messagebox
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

PREDEFINED_FOLDER = "path/to/predefined/folder"  # Replace with your predefined folder path

def get_cert_expiration_date(cert_path):
    try:
        with open(cert_path, 'rb') as cert_file:
            cert_data = cert_file.read()

        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        return cert.not_valid_after
    except Exception:
        return None

def check_certificates(folder_path):
    result_list.delete(*result_list.get_children())
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.endswith(('.cer', '.crt', '.txt')):
                file_path = os.path.join(root, file)
                expiration_date = get_cert_expiration_date(file_path)
                if expiration_date:
                    status = get_cert_status(expiration_date)
                    result_list.insert('', tk.END, values=(file, status, expiration_date.strftime('%Y-%m-%d')))
                else:
                    result_list.insert('', tk.END, values=(file, "Invalid or unreadable", ""))

def get_cert_status(expiration_date):
    today = datetime.today()
    if expiration_date < today:
        return "Expired"
    elif expiration_date < (today + timedelta(days=30)):
        return "Needs updating"
    else:
        return "Valid"

def load_folder():
    global current_folder
    current_folder = filedialog.askdirectory(initialdir=PREDEFINED_FOLDER)
    if current_folder:
        check_certificates(current_folder)

def refresh_status():
    if current_folder:
        check_certificates(current_folder)
    else:
        messagebox.showinfo("Information", "Please select a folder first.")

# AES Encryption/Decryption Functions
def aes_encrypt():
    key = aes_key_entry.get()
    plaintext = aes_input_entry.get()
    try:
        cipher = AES.new(pad(key.encode(), AES.block_size), AES.MODE_ECB)
        encrypted = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
        aes_output_text.delete('1.0', tk.END)
        aes_output_text.insert(tk.END, encrypted.hex())
    except Exception as e:
        messagebox.showerror("Encryption Error", str(e))

def aes_decrypt():
    key = aes_key_entry.get()
    encrypted_text = aes_input_entry.get()
    try:
        cipher = AES.new(pad(key.encode(), AES.block_size), AES.MODE_ECB)
        decrypted = unpad(cipher.decrypt(bytes.fromhex(encrypted_text)), AES.block_size)
        aes_output_text.delete('1.0', tk.END)
        aes_output_text.insert(tk.END, decrypted.decode())
    except Exception as e:
        messagebox.showerror("Decryption Error", str(e))

# Create main window
root = tk.Tk()
root.title("Utility Application")

tab_control = ttk.Notebook(root)

# Certificate Tab
cert_tab = ttk.Frame(tab_control)
tab_control.add(cert_tab, text="Certificate Checker")

# Certificate Checker Widgets
load_button = tk.Button(cert_tab, text="Select Folder", command=load_folder)
load_button.pack(pady=10)

refresh_button = tk.Button(cert_tab, text="Check/Refresh Status", command=refresh_status)
refresh_button.pack(pady=10)

cols = ('Certificate File', 'Status', 'Expiration Date')
result_list = ttk.Treeview(cert_tab, columns=cols, show='headings')
for col in cols:
    result_list.heading(col, text=col)
result_list.pack(expand=True, fill='both')

check_certificates(PREDEFINED_FOLDER)

# AES Tab
aes_tab = ttk.Frame(tab_control)
tab_control.add(aes_tab, text="AES Encryption/Decryption")

# AES Widgets
tk.Label(aes_tab, text="Key:").pack()
aes_key_entry = tk.Entry(aes_tab)
aes_key_entry.pack()

tk.Label(aes_tab, text="Input Text:").pack()
aes_input_entry = tk.Entry(aes_tab)
aes_input_entry.pack()

encrypt_button = tk.Button(aes_tab, text="Encrypt", command=aes_encrypt)
encrypt_button.pack()

decrypt_button = tk.Button(aes_tab, text="Decrypt", command=aes_decrypt)
decrypt_button.pack()

aes_output_text = tk.Text(aes_tab, height=5, width=50)
aes_output_text.pack()

# Finish setup
tab_control.pack(expand=1, fill="both")

root.mainloop()
