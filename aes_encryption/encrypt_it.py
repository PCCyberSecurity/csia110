import tkinter as tk
from tkinter import ttk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

# Encryption / Decryption Functions
def encrypt_message(message, key):
    key_bytes = key.encode().ljust(32, b'\0')[:32]  # Ensure 32 bytes for AES-256
    nonce = os.urandom(16)  # 128-bit nonce
    cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(message.encode()) + encryptor.finalize()
    return base64.b64encode(nonce + encrypted).decode()

def decrypt_message(enc_data_b64, key):
    key_bytes = key.encode().ljust(32, b'\0')[:32]
    try:
        enc_data = base64.b64decode(enc_data_b64)
        nonce = enc_data[:16]
        encrypted = enc_data[16:]
        cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted) + decryptor.finalize()
        return decrypted.decode()
    except Exception as e:
        return f"Error: {str(e)}"

# GUI App
class EncryptApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AES Encryption/Decryption")
        self.font_size = 12

        # Text Boxes and Labels
        self.message_label = ttk.Label(root, text="Message:")
        self.message_text = tk.Text(root, height=4, font=("Arial", self.font_size))

        self.key_label = ttk.Label(root, text="Key:")
        self.key_entry = ttk.Entry(root, font=("Arial", self.font_size))

        self.encrypted_label = ttk.Label(root, text="Encrypted (base64):")
        self.encrypted_text = tk.Text(root, height=4, font=("Arial", self.font_size))

        self.decrypted_label = ttk.Label(root, text="Decrypted:")
        self.decrypted_text = tk.Text(root, height=4, font=("Arial", self.font_size))

        # Buttons
        self.encrypt_button = ttk.Button(root, text="Encrypt", command=self.encrypt)
        self.decrypt_button = ttk.Button(root, text="Decrypt", command=self.decrypt)
        self.font_increase = ttk.Button(root, text="A+", command=self.increase_font)
        self.font_decrease = ttk.Button(root, text="A-", command=self.decrease_font)

        # Layout
        self.message_label.grid(row=0, column=0, sticky='w')
        self.message_text.grid(row=1, column=0, columnspan=4, padx=5, pady=5, sticky='ew')

        self.key_label.grid(row=2, column=0, sticky='w')
        self.key_entry.grid(row=3, column=0, columnspan=4, padx=5, pady=5, sticky='ew')

        self.encrypt_button.grid(row=4, column=0, pady=5)
        self.decrypt_button.grid(row=4, column=1, pady=5)
        self.font_increase.grid(row=4, column=2, pady=5)
        self.font_decrease.grid(row=4, column=3, pady=5)

        self.encrypted_label.grid(row=5, column=0, sticky='w')
        self.encrypted_text.grid(row=6, column=0, columnspan=4, padx=5, pady=5, sticky='ew')

        self.decrypted_label.grid(row=7, column=0, sticky='w')
        self.decrypted_text.grid(row=8, column=0, columnspan=4, padx=5, pady=5, sticky='ew')

        # Make window resizable
        for i in range(4):
            root.columnconfigure(i, weight=1)

    def encrypt(self):
        message = self.message_text.get("1.0", tk.END).strip()
        key = self.key_entry.get()
        encrypted = encrypt_message(message, key)
        self.encrypted_text.delete("1.0", tk.END)
        self.encrypted_text.insert(tk.END, encrypted)

    def decrypt(self):
        enc_data = self.encrypted_text.get("1.0", tk.END).strip()
        key = self.key_entry.get()
        decrypted = decrypt_message(enc_data, key)
        self.decrypted_text.delete("1.0", tk.END)
        self.decrypted_text.insert(tk.END, decrypted)

    def update_fonts(self):
        widgets = [self.message_text, self.key_entry, self.encrypted_text, self.decrypted_text]
        for widget in widgets:
            widget.config(font=("Arial", self.font_size))

    def increase_font(self):
        self.font_size += 1
        self.update_fonts()

    def decrease_font(self):
        if self.font_size > 6:
            self.font_size -= 1
            self.update_fonts()

# Run App
if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptApp(root)
    root.mainloop()
