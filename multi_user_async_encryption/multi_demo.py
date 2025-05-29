import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

class SecureMessengerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Messaging Between Two Users (RSA)")
        self.font_size = 11

        # Keys
        self.user1_private = None
        self.user1_public = None
        self.user2_private = None
        self.user2_public = None

        self.setup_gui()

    def setup_gui(self):
        pad = 5
        bold = ("Arial", self.font_size, "bold")

        # ---------------- User 1 ----------------
        ttk.Label(root, text="User 1 Message:", font=bold).grid(row=0, column=0, sticky="w", padx=pad)
        self.user1_input = tk.Text(root, height=3, font=("Courier", self.font_size))
        self.user1_input.grid(row=1, column=0, padx=pad, pady=pad, sticky="ew")

        ttk.Button(root, text="Encrypt to User 2", command=self.encrypt_to_user2).grid(row=2, column=0, padx=pad)
        ttk.Button(root, text="Decrypt (User 1)", command=self.decrypt_user1).grid(row=3, column=0, padx=pad)

        ttk.Label(root, text="User 1 Encrypted/Decrypted:", font=bold).grid(row=4, column=0, sticky="w", padx=pad)
        self.user1_output = tk.Text(root, height=3, font=("Courier", self.font_size))
        self.user1_output.grid(row=5, column=0, padx=pad, pady=pad, sticky="ew")

        ttk.Button(root, text="Generate User 1 Keys", command=lambda: self.generate_keys(1)).grid(row=6, column=0, sticky="w", padx=pad)
        ttk.Button(root, text="Load User 1 Public Key", command=lambda: self.load_key(1, public=True)).grid(row=6, column=0)
        ttk.Button(root, text="Load User 1 Private Key", command=lambda: self.load_key(1, public=False)).grid(row=6, column=0, sticky="e", padx=pad)

        ttk.Label(root, text="User 1 Public Key:").grid(row=7, column=0, sticky="w")
        self.user1_pub_text = tk.Text(root, height=4, font=("Courier", self.font_size), wrap="none")
        self.user1_pub_text.grid(row=8, column=0, padx=pad, pady=pad, sticky="ew")

        ttk.Label(root, text="User 1 Private Key:").grid(row=9, column=0, sticky="w")
        self.user1_priv_text = tk.Text(root, height=4, font=("Courier", self.font_size), wrap="none")
        self.user1_priv_text.grid(row=10, column=0, padx=pad, pady=pad, sticky="ew")

        # ---------------- User 2 ----------------
        ttk.Label(root, text="User 2 Message:", font=bold).grid(row=0, column=1, sticky="w", padx=pad)
        self.user2_input = tk.Text(root, height=3, font=("Courier", self.font_size))
        self.user2_input.grid(row=1, column=1, padx=pad, pady=pad, sticky="ew")

        ttk.Button(root, text="Encrypt to User 1", command=self.encrypt_to_user1).grid(row=2, column=1, padx=pad)
        ttk.Button(root, text="Decrypt (User 2)", command=self.decrypt_user2).grid(row=3, column=1, padx=pad)

        ttk.Label(root, text="User 2 Encrypted/Decrypted:", font=bold).grid(row=4, column=1, sticky="w", padx=pad)
        self.user2_output = tk.Text(root, height=3, font=("Courier", self.font_size))
        self.user2_output.grid(row=5, column=1, padx=pad, pady=pad, sticky="ew")

        ttk.Button(root, text="Generate User 2 Keys", command=lambda: self.generate_keys(2)).grid(row=6, column=1, sticky="w", padx=pad)
        ttk.Button(root, text="Load User 2 Public Key", command=lambda: self.load_key(2, public=True)).grid(row=6, column=1)
        ttk.Button(root, text="Load User 2 Private Key", command=lambda: self.load_key(2, public=False)).grid(row=6, column=1, sticky="e", padx=pad)

        ttk.Label(root, text="User 2 Public Key:").grid(row=7, column=1, sticky="w")
        self.user2_pub_text = tk.Text(root, height=4, font=("Courier", self.font_size), wrap="none")
        self.user2_pub_text.grid(row=8, column=1, padx=pad, pady=pad, sticky="ew")

        ttk.Label(root, text="User 2 Private Key:").grid(row=9, column=1, sticky="w")
        self.user2_priv_text = tk.Text(root, height=4, font=("Courier", self.font_size), wrap="none")
        self.user2_priv_text.grid(row=10, column=1, padx=pad, pady=pad, sticky="ew")

        # Font Controls
        ttk.Button(root, text="A+", command=self.increase_font).grid(row=11, column=0, sticky="w", padx=pad, pady=pad)
        ttk.Button(root, text="A-", command=self.decrease_font).grid(row=11, column=1, sticky="e", padx=pad, pady=pad)

        for i in range(2):
            root.columnconfigure(i, weight=1)

    def update_fonts(self):
        widgets = [
            self.user1_input, self.user1_output, self.user1_pub_text, self.user1_priv_text,
            self.user2_input, self.user2_output, self.user2_pub_text, self.user2_priv_text
        ]
        for w in widgets:
            w.config(font=("Courier", self.font_size))

    def increase_font(self):
        self.font_size += 1
        self.update_fonts()

    def decrease_font(self):
        if self.font_size > 6:
            self.font_size -= 1
            self.update_fonts()

    def generate_keys(self, user):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        if user == 1:
            self.user1_private = private_key
            self.user1_public = public_key
            self.user1_priv_text.delete("1.0", tk.END)
            self.user1_pub_text.delete("1.0", tk.END)
            self.user1_priv_text.insert(tk.END, priv_pem.decode())
            self.user1_pub_text.insert(tk.END, pub_pem.decode())
        else:
            self.user2_private = private_key
            self.user2_public = public_key
            self.user2_priv_text.delete("1.0", tk.END)
            self.user2_pub_text.delete("1.0", tk.END)
            self.user2_priv_text.insert(tk.END, priv_pem.decode())
            self.user2_pub_text.insert(tk.END, pub_pem.decode())

    def load_key(self, user, public=True):
        path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")])
        if not path: return
        with open(path, "rb") as f:
            data = f.read()

        try:
            if public:
                key = serialization.load_pem_public_key(data)
                if user == 1:
                    self.user1_public = key
                    self.user1_pub_text.delete("1.0", tk.END)
                    self.user1_pub_text.insert(tk.END, data.decode())
                else:
                    self.user2_public = key
                    self.user2_pub_text.delete("1.0", tk.END)
                    self.user2_pub_text.insert(tk.END, data.decode())
            else:
                key = serialization.load_pem_private_key(data, password=None)
                if user == 1:
                    self.user1_private = key
                    self.user1_priv_text.delete("1.0", tk.END)
                    self.user1_priv_text.insert(tk.END, data.decode())
                else:
                    self.user2_private = key
                    self.user2_priv_text.delete("1.0", tk.END)
                    self.user2_priv_text.insert(tk.END, data.decode())
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load key: {e}")

    def encrypt_message(self, msg, pub_key):
        encrypted = pub_key.encrypt(
            msg.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted).decode()

    def decrypt_message(self, encoded_msg, priv_key):
        try:
            encrypted = base64.b64decode(encoded_msg)
            decrypted = priv_key.decrypt(
                encrypted,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted.decode()
        except Exception as e:
            return f"Decryption Error: {e}"

    def encrypt_to_user2(self):
        if not self.user2_public:
            messagebox.showerror("Error", "User 2 public key not loaded.")
            return
        msg = self.user1_input.get("1.0", tk.END).strip()
        enc = self.encrypt_message(msg, self.user2_public)
        self.user1_output.delete("1.0", tk.END)
        self.user1_output.insert(tk.END, enc)
        self.user2_input.delete("1.0", tk.END)
        self.user2_input.insert(tk.END, enc)

    def decrypt_user2(self):
        if not self.user2_private:
            messagebox.showerror("Error", "User 2 private key not loaded.")
            return
        msg = self.user2_input.get("1.0", tk.END).strip()
        dec = self.decrypt_message(msg, self.user2_private)
        self.user2_output.delete("1.0", tk.END)
        self.user2_output.insert(tk.END, dec)

    def encrypt_to_user1(self):
        if not self.user1_public:
            messagebox.showerror("Error", "User 1 public key not loaded.")
            return
        msg = self.user2_input.get("1.0", tk.END).strip()
        enc = self.encrypt_message(msg, self.user1_public)
        self.user2_output.delete("1.0", tk.END)
        self.user2_output.insert(tk.END, enc)
        self.user1_input.delete("1.0", tk.END)
        self.user1_input.insert(tk.END, enc)

    def decrypt_user1(self):
        if not self.user1_private:
            messagebox.showerror("Error", "User 1 private key not loaded.")
            return
        msg = self.user1_input.get("1.0", tk.END).strip()
        dec = self.decrypt_message(msg, self.user1_private)
        self.user1_output.delete("1.0", tk.END)
        self.user1_output.insert(tk.END, dec)

# Run app
if __name__ == "__main__":
    root = tk.Tk()
    app = SecureMessengerApp(root)
    root.mainloop()
