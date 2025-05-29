import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

class RSAEncryptApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Asymmetric RSA Encryption Tool")
        self.font_size = 12

        self.private_key = None
        self.public_key = None

        # GUI Setup
        self.create_widgets()

    def create_widgets(self):
        # Labels and Text Areas
        self.input_label = ttk.Label(root, text="Input Message:")
        self.input_text = tk.Text(root, height=4, font=("Arial", self.font_size))

        self.output_label = ttk.Label(root, text="Output:")
        self.output_text = tk.Text(root, height=4, font=("Arial", self.font_size))

        self.public_label = ttk.Label(root, text="Public Key:")
        self.public_text = tk.Text(root, height=5, font=("Courier", self.font_size), wrap="none")

        self.private_label = ttk.Label(root, text="Private Key:")
        self.private_text = tk.Text(root, height=5, font=("Courier", self.font_size), wrap="none")

        # Buttons
        self.generate_keys_btn = ttk.Button(root, text="Generate Keys", command=self.generate_keys)
        self.load_private_btn = ttk.Button(root, text="Load Private Key", command=self.load_private_key)
        self.load_public_btn = ttk.Button(root, text="Load Public Key", command=self.load_public_key)

        self.encrypt_btn = ttk.Button(root, text="Encrypt", command=self.encrypt_message)
        self.decrypt_btn = ttk.Button(root, text="Decrypt", command=self.decrypt_message)

        self.font_increase_btn = ttk.Button(root, text="A+", command=self.increase_font)
        self.font_decrease_btn = ttk.Button(root, text="A-", command=self.decrease_font)

        # Layout
        self.input_label.grid(row=0, column=0, sticky="w")
        self.input_text.grid(row=1, column=0, columnspan=4, padx=5, pady=5, sticky="ew")

        self.output_label.grid(row=2, column=0, sticky="w")
        self.output_text.grid(row=3, column=0, columnspan=4, padx=5, pady=5, sticky="ew")

        self.public_label.grid(row=4, column=0, sticky="w")
        self.public_text.grid(row=5, column=0, columnspan=4, padx=5, pady=5, sticky="ew")

        self.private_label.grid(row=6, column=0, sticky="w")
        self.private_text.grid(row=7, column=0, columnspan=4, padx=5, pady=5, sticky="ew")

        self.generate_keys_btn.grid(row=8, column=0, pady=5)
        self.load_private_btn.grid(row=8, column=1, pady=5)
        self.load_public_btn.grid(row=8, column=2, pady=5)
        self.font_increase_btn.grid(row=8, column=3, pady=5)

        self.encrypt_btn.grid(row=9, column=0, pady=5)
        self.decrypt_btn.grid(row=9, column=1, pady=5)
        self.font_decrease_btn.grid(row=9, column=2, pady=5)

        for i in range(4):
            root.columnconfigure(i, weight=1)

    def update_fonts(self):
        widgets = [
            self.input_text, self.output_text,
            self.public_text, self.private_text
        ]
        for widget in widgets:
            widget.config(font=("Courier", self.font_size))

    def increase_font(self):
        self.font_size += 1
        self.update_fonts()

    def decrease_font(self):
        if self.font_size > 6:
            self.font_size -= 1
            self.update_fonts()

    def show_keys(self):
        # Display current public and private keys (if available)
        self.public_text.delete("1.0", tk.END)
        self.private_text.delete("1.0", tk.END)

        if self.public_key:
            pub_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            self.public_text.insert(tk.END, pub_pem.decode())

        if self.private_key:
            priv_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            self.private_text.insert(tk.END, priv_pem.decode())

    def generate_keys(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()

        # Save to files
        with open("private_key.pem", "wb") as f:
            f.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        with open("public_key.pem", "wb") as f:
            f.write(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        messagebox.showinfo("Keys Generated", "Saved as 'private_key.pem' and 'public_key.pem'")
        self.show_keys()

    def load_private_key(self):
        path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")])
        if path:
            with open(path, "rb") as f:
                self.private_key = serialization.load_pem_private_key(f.read(), password=None)
            messagebox.showinfo("Loaded", "Private key loaded.")
            self.show_keys()

    def load_public_key(self):
        path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")])
        if path:
            with open(path, "rb") as f:
                self.public_key = serialization.load_pem_public_key(f.read())
            messagebox.showinfo("Loaded", "Public key loaded.")
            self.show_keys()

    def encrypt_message(self):
        message = self.input_text.get("1.0", tk.END).strip()
        if not self.public_key:
            messagebox.showerror("Error", "Public key is not loaded.")
            return

        try:
            encrypted = self.public_key.encrypt(
                message.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            encoded = base64.b64encode(encrypted).decode()
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, encoded)
        except Exception as e:
            self.output_text.insert(tk.END, f"Error: {e}")

    def decrypt_message(self):
        enc_message = self.input_text.get("1.0", tk.END).strip()
        if not self.private_key:
            messagebox.showerror("Error", "Private key is not loaded.")
            return

        try:
            encrypted = base64.b64decode(enc_message)
            decrypted = self.private_key.decrypt(
                encrypted,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, decrypted.decode())
        except Exception as e:
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, f"Error: {e}")

# Run app
if __name__ == "__main__":
    root = tk.Tk()
    app = RSAEncryptApp(root)
    root.mainloop()
