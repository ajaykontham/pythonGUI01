import tkinter as tk
from tkinter import filedialog, ttk
import os
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.backends import default_backend

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

# Create main window
root = tk.Tk()
root.title("Certificate Expiration Checker")

current_folder = PREDEFINED_FOLDER  # Initialize current folder

# Create and place widgets
load_button = tk.Button(root, text="Select Folder", command=load_folder)
load_button.pack(pady=10)

refresh_button = tk.Button(root, text="Check/Refresh Status", command=refresh_status)
refresh_button.pack(pady=10)

# Result tree view
cols = ('Certificate File', 'Status', 'Expiration Date')
result_list = ttk.Treeview(root, columns=cols, show='headings')
for col in cols:
    result_list.heading(col, text=col)
result_list.pack(expand=True, fill='both')

# Initial check in predefined folder
check_certificates(PREDEFINED_FOLDER)

# Run the application
root.mainloop()
