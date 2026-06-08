import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.scrolledtext import ScrolledText

from rsa_keygen import RSAKeyGen
from symmetric_core import HybridCrypto


class HybridCryptoGUI:

    def __init__(self, root):

        self.root = root
        self.root.title("HỆ MÃ LAI RSA - AES")
        self.root.geometry("700x500")

        self.selected_file = ""

        self.create_widgets()

    def create_widgets(self):

        title = tk.Label(
            self.root,
            text="ỨNG DỤNG MÃ HÓA FILE RSA - AES",
            font=("Arial", 16, "bold")
        )

        title.pack(pady=15)

        frame = tk.Frame(self.root)
        frame.pack(pady=10)

        self.path_label = tk.Label(
            frame,
            text="Chưa chọn file",
            width=60,
            anchor="w"
        )

        self.path_label.grid(
            row=0,
            column=0,
            padx=5
        )

        browse_btn = tk.Button(
            frame,
            text="Chọn File",
            width=15,
            command=self.choose_file
        )

        browse_btn.grid(
            row=0,
            column=1,
            padx=5
        )

        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=20)

        key_btn = tk.Button(
            btn_frame,
            text="Sinh Khóa RSA",
            width=18,
            height=2,
            command=self.generate_keys
        )

        key_btn.grid(row=0, column=0, padx=10)

        encrypt_btn = tk.Button(
            btn_frame,
            text="Mã Hóa",
            width=18,
            height=2,
            command=self.encrypt_file
        )

        encrypt_btn.grid(row=0, column=1, padx=10)

        decrypt_btn = tk.Button(
            btn_frame,
            text="Giải Mã",
            width=18,
            height=2,
            command=self.decrypt_file
        )

        decrypt_btn.grid(row=0, column=2, padx=10)

        self.log_box = ScrolledText(
            self.root,
            width=80,
            height=15
        )

        self.log_box.pack(pady=15)

    def log(self, text):

        self.log_box.insert(tk.END, text + "\n")
        self.log_box.see(tk.END)

    def choose_file(self):

        file_path = filedialog.askopenfilename()

        if file_path:

            self.selected_file = file_path

            self.path_label.config(
                text=file_path
            )

            self.log(
                f"Đã chọn file: {file_path}"
            )

    def generate_keys(self):

        try:

            self.log("Đang sinh khóa RSA...")

            public_key, private_key = (
                RSAKeyGen.generate_keypair()
            )

            RSAKeyGen.save_keys(
                public_key,
                private_key
            )

            self.log(
                "Sinh khóa thành công"
            )

            messagebox.showinfo(
                "Thông báo",
                "Đã sinh khóa RSA"
            )

        except Exception as e:

            messagebox.showerror(
                "Lỗi",
                str(e)
            )

    def encrypt_file(self):

        if not self.selected_file:

            messagebox.showwarning(
                "Thông báo",
                "Vui lòng chọn file"
            )

            return

        try:

            self.log("Bắt đầu mã hóa...")

            result = (
                HybridCrypto.encrypt_file(
                    self.selected_file
                )
            )

            self.log(
                f"Mã hóa thành công:\n{result}"
            )

            messagebox.showinfo(
                "Thông báo",
                "Mã hóa thành công"
            )

        except Exception as e:

            messagebox.showerror(
                "Lỗi",
                str(e)
            )

    def decrypt_file(self):

        if not self.selected_file:

            messagebox.showwarning(
                "Thông báo",
                "Vui lòng chọn file"
            )

            return

        try:

            self.log("Bắt đầu giải mã...")

            result = (
                HybridCrypto.decrypt_file(
                    self.selected_file
                )
            )

            self.log(
                f"Giải mã thành công:\n{result}"
            )

            messagebox.showinfo(
                "Thông báo",
                "Giải mã thành công"
            )

        except Exception as e:

            messagebox.showerror(
                "Lỗi",
                str(e)
            )