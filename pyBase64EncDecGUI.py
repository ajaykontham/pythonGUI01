import tkinter as tk
import base64

# Function to encode
def encode_base64():
    input_text = input_entry.get()
    encoded = base64.b64encode(input_text.encode()).decode()
    output_text.delete('1.0', tk.END)
    output_text.insert(tk.END, encoded)

def encode_base64_CS():
    input_text_clientId = input_entry_clientId.get()
    input_text_clientSec= input_entry_clientSec.get()
    encoded = base64.b64encode((input_text_clientId +":"+input_text_clientSec).encode()).decode()
    output_textCS.delete('1.0', tk.END)
    output_textCS.insert(tk.END, encoded)

# Function to decode
def decode_base64():
    input_text = input_entry.get()
    try:
        decoded = base64.b64decode(input_text).decode()
        output_text.delete('1.0', tk.END)
        output_text.insert(tk.END, decoded)
    except Exception as e:
        output_text.delete('1.0', tk.END)
        output_text.insert(tk.END, f"Error: {e}")

# Create main window
root = tk.Tk()
root.title("Base64 Encode/Decode")

# Create and place widgets
tk.Label(root, text="Input:").grid(row=0, column=0)
input_entry = tk.Entry(root, width=50)
input_entry.grid(row=0, column=1)

encode_button = tk.Button(root, text="Encode", command=encode_base64)
encode_button.grid(row=1, column=0)

decode_button = tk.Button(root, text="Decode", command=decode_base64)
decode_button.grid(row=1, column=1)

output_text = tk.Text(root, height=5, width=50)
output_text.grid(row=2, column=0, columnspan=2)


tk.Label(root, text="ClientId:").grid(row=3, column=0)
input_entry_clientId = tk.Entry(root, width=50)
input_entry_clientId.grid(row=3, column=1)

tk.Label(root, text="ClientSecret:").grid(row=4, column=0)
input_entry_clientSec = tk.Entry(root, width=50)
input_entry_clientSec.grid(row=4, column=1)

encode_buttonCS = tk.Button(root, text="Encode", command=encode_base64_CS)
encode_buttonCS.grid(row=5, column=1)

# decode_button = tk.Button(root, text="Decode", command=decode_base64)
# decode_button.grid(row=1, column=1)

output_textCS = tk.Text(root, height=5, width=50)
output_textCS.grid(row=6, column=0, columnspan=2)

# Run the application
root.mainloop()
