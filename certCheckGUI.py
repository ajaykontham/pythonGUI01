import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend

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
                    result_list.insert('', tk.END, values=(file, expiration_date))
                else:
                    result_list.insert('', tk.END, values=(file, "Invalid or unreadable"))

def load_folder():
    folder_path = filedialog.askdirectory()
    if folder_path:
        check_certificates(folder_path)

# Create main window
root = tk.Tk()
root.title("Certificate Expiration Checker")

# Create and place widgets
load_button = tk.Button(root, text="Load Folder", command=load_folder)
load_button.pack(pady=10)

# Result tree view
cols = ('Certificate File', 'Expiration Date')
result_list = ttk.Treeview(root, columns=cols, show='headings')
for col in cols:
    result_list.heading(col, text=col)
result_list.pack(expand=True, fill='both')

# Run the application
root.mainloop()