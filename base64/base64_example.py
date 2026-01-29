import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk
import base64

class Base64ConverterApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Base64 Converter")
        self.font_size = 22

        # Widgets
        self.input_label = ttk.Label(root, text="Input:")
        self.input_text = tk.Text(root, height=5, font=("Arial", self.font_size))

        self.output_label = ttk.Label(root, text="Output:")
        self.output_text = tk.Text(root, height=5, font=("Arial", self.font_size))

        self.encode_button = ttk.Button(root, text="To Base64", command=self.encode_base64)
        self.decode_button = ttk.Button(root, text="From Base64", command=self.decode_base64)
        self.font_increase_button = ttk.Button(root, text="A+", command=self.increase_font)
        self.font_decrease_button = ttk.Button(root, text="A-", command=self.decrease_font)

        # Layout
        self.input_label.grid(row=0, column=0, sticky='w')
        self.input_text.grid(row=1, column=0, columnspan=4, padx=5, pady=5, sticky='ew')

        self.encode_button.grid(row=2, column=0, pady=5)
        self.decode_button.grid(row=2, column=1, pady=5)
        self.font_increase_button.grid(row=2, column=2, pady=5)
        self.font_decrease_button.grid(row=2, column=3, pady=5)

        self.output_label.grid(row=3, column=0, sticky='w')
        self.output_text.grid(row=4, column=0, columnspan=4, padx=5, pady=5, sticky='ew')

        # Make columns expandable
        for i in range(4):
            root.columnconfigure(i, weight=1)

    def encode_base64(self):
        input_text = self.input_text.get("1.0", tk.END).strip()
        try:
            encoded = base64.b64encode(input_text.encode()).decode()
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, encoded)
        except Exception as e:
            self.output_text.insert(tk.END, f"Error: {str(e)}")

    def decode_base64(self):
        input_text = self.input_text.get("1.0", tk.END).strip()
        try:
            decoded = base64.b64decode(input_text).decode()
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, decoded)
        except Exception as e:
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, f"Error: {str(e)}")

    def update_fonts(self):
        widgets = [self.input_text, self.output_text]
        for widget in widgets:
            widget.config(font=("Arial", self.font_size))

    def increase_font(self):
        self.font_size += 1
        self.update_fonts()

    def decrease_font(self):
        if self.font_size > 6:
            self.font_size -= 1
            self.update_fonts()

# Run the app
if __name__ == "__main__":
    root = tk.Tk()
    # Set default font for all widgets
    default_font = tkfont.nametofont("TkDefaultFont")
    default_font.configure(size=22)
    root.option_add("*Font", default_font)
    app = Base64ConverterApp(root)
    root.mainloop()
