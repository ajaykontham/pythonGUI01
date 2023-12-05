import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def load_certificate():
    file_path = filedialog.askopenfilename()
    if file_path:
        expiration_date = get_cert_expiration_date(file_path)
        if expiration_date:
            result_label.config(text=f"Expiration Date: {expiration_date}")
        else:
            result_label.config(text="Invalid certificate or error in reading.")

def get_cert_expiration_date(cert_path):
    try:
        with open(cert_path, 'rb') as cert_file:
            cert_data = cert_file.read()

        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        return cert.not_valid_after
    except Exception as e:
        messagebox.showerror("Error", str(e))
        return None

# Create main window
root = tk.Tk()
root.title("Certificate Expiration Checker")

# Create and place widgets
load_button = tk.Button(root, text="Load Certificate", command=load_certificate)
load_button.pack(pady=10)

result_label = tk.Label(root, text="Expiration Date: Not Checked")
result_label.pack(pady=10)

# Run the application
root.mainloop()
