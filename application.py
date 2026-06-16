import customtkinter as ctk
from tkinter import filedialog, messagebox
import time

from rsa_keygen import RSAKeyGen
from symmetric_core import HybridCrypto

ctk.set_appearance_mode("light")
ctk.set_default_color_theme("blue")


class ModernHybridCryptoGUI:

    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ HỆ THỐNG MÃ HÓA LAI RSA - AES | Nhóm 10_S3")
        self.root.geometry("880x720")
        self.root.minsize(880, 720)

        self.root.configure(fg_color="#F3F4F6")

        self.selected_file = ""
        self.create_widgets()

    def create_widgets(self):
   
        self.header_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        self.header_frame.pack(pady=(30, 20), fill="x", padx=40)

        self.title_label = ctk.CTkLabel(
            self.header_frame,
            text="HỆ THỐNG MÃ HÓA BẢO MẬT",
            font=ctk.CTkFont(family="Segoe UI", size=28, weight="bold"),
            text_color="#1E3A8A"
        )
        self.title_label.pack(anchor="center")

        self.subtitle_label = ctk.CTkLabel(
            self.header_frame,
            text="Giải pháp mã hóa lai RSA-AES toàn diện • Đảm bảo tính toàn vẹn dữ liệu",
            font=ctk.CTkFont(family="Segoe UI", size=14),
            text_color="#6B7280"  
        )
        self.subtitle_label.pack(anchor="center", pady=(5, 0))

        self.file_card = ctk.CTkFrame(
            self.root, 
            corner_radius=15, 
            fg_color="#FFFFFF", 
            border_width=1, 
            border_color="#E5E7EB"
        )
        self.file_card.pack(pady=(0, 15), fill="x", padx=40)

        self.file_title_frame = ctk.CTkFrame(self.file_card, fg_color="transparent")
        self.file_title_frame.pack(fill="x", padx=20, pady=(15, 5))
        
        self.file_icon = ctk.CTkLabel(self.file_title_frame, text="📄", font=ctk.CTkFont(size=18))
        self.file_icon.pack(side="left", padx=(0, 5))

        self.file_title = ctk.CTkLabel(
            self.file_title_frame,
            text="TỆP TIN XỬ LÝ ĐẦU VÀO",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color="#374151"
        )
        self.file_title.pack(side="left")

        self.file_action_frame = ctk.CTkFrame(self.file_card, fg_color="transparent")
        self.file_action_frame.pack(fill="x", padx=20, pady=(0, 20))

        self.path_entry = ctk.CTkEntry(
            self.file_action_frame,
            placeholder_text="Vui lòng tải lên dữ liệu cần bảo mật...",
            font=ctk.CTkFont(family="Segoe UI", size=14),
            height=45,
            fg_color="#F9FAFB",
            border_color="#D1D5DB",
            text_color="#111827",
            state="disabled",
            corner_radius=8
        )
        self.path_entry.pack(side="left", fill="x", expand=True, padx=(0, 15))

        self.browse_btn = ctk.CTkButton(
            self.file_action_frame,
            text="Duyệt Tệp...",
            font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
            width=140,
            height=45,
            corner_radius=8,
            fg_color="#3B82F6",
            hover_color="#2563EB",
            command=self.choose_file
        )
        self.browse_btn.pack(side="right")

        self.action_card = ctk.CTkFrame(
            self.root, 
            corner_radius=15, 
            fg_color="#FFFFFF", 
            border_width=1, 
            border_color="#E5E7EB"
        )
        self.action_card.pack(pady=0, fill="x", padx=40)

        self.buttons_frame = ctk.CTkFrame(self.action_card, fg_color="transparent")
        self.buttons_frame.pack(fill="x", padx=20, pady=25)

        self.buttons_frame.columnconfigure(0, weight=1)
        self.buttons_frame.columnconfigure(1, weight=1)
        self.buttons_frame.columnconfigure(2, weight=1)
        self.key_btn = ctk.CTkButton(
            self.buttons_frame,
            text="🔑 Tạo Khóa RSA",
            font=ctk.CTkFont(family="Segoe UI", size=15, weight="bold"),
            height=50,
            corner_radius=10,
            fg_color="#8B5CF6",
            hover_color="#7C3AED",
            command=self.generate_keys
        )
        self.key_btn.grid(row=0, column=0, padx=(0, 10), sticky="ew")

        self.encrypt_btn = ctk.CTkButton(
            self.buttons_frame,
            text="🔒 Mã Hóa Dữ Liệu",
            font=ctk.CTkFont(family="Segoe UI", size=15, weight="bold"),
            height=50,
            corner_radius=10,
            fg_color="#F97316",
            hover_color="#EA580C",
            command=self.encrypt_file
        )
        self.encrypt_btn.grid(row=0, column=1, padx=5, sticky="ew")

        self.decrypt_btn = ctk.CTkButton(
            self.buttons_frame,
            text="🔓 Giải Mã & Khôi Phục",
            font=ctk.CTkFont(family="Segoe UI", size=15, weight="bold"),
            height=50,
            corner_radius=10,
            fg_color="#10B981",
            hover_color="#059669",
            command=self.decrypt_file
        )
        self.decrypt_btn.grid(row=0, column=2, padx=(10, 0), sticky="ew")

        self.log_card = ctk.CTkFrame(
            self.root, 
            corner_radius=15, 
            fg_color="#FFFFFF", 
            border_width=1, 
            border_color="#E5E7EB"
        )
        self.log_card.pack(pady=15, fill="both", expand=True, padx=40)

        self.log_header = ctk.CTkFrame(self.log_card, fg_color="#F8FAFC", height=40, corner_radius=15)
        self.log_header.pack(fill="x", side="top", padx=2, pady=2)

        self.log_title = ctk.CTkLabel(
            self.log_header,
            text=" ⚙️ NHẬT KÝ HOẠT ĐỘNG (SYSTEM LOG)",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color="#475569"
        )
        self.log_title.pack(side="left", padx=15, pady=8)

        self.log_box = ctk.CTkTextbox(
            self.log_card,
            font=ctk.CTkFont(family="Consolas", size=13),
            fg_color="#FFFFFF",
            text_color="#1F2937", 
            corner_radius=10,
            border_width=0
        )
        self.log_box.pack(fill="both", expand=True, padx=15, pady=(0, 15))


        self.status_bar = ctk.CTkFrame(self.root, fg_color="#E5E7EB", height=30, corner_radius=0)
        self.status_bar.pack(fill="x", side="bottom")

        self.status_label = ctk.CTkLabel(
            self.status_bar,
            text="Trạng thái: Sẵn sàng hoạt động",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color="#374151"
        )
        self.status_label.pack(side="left", padx=15)

        self.version_label = ctk.CTkLabel(
            self.status_bar,
            text="Phiên bản: 2.0.1 | Hybrid Crypto Engine",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color="#6B7280"
        )
        self.version_label.pack(side="right", padx=15)

    def set_status(self, text, is_working=False):
        prefix = "⏳ Đang xử lý: " if is_working else "✅ Trạng thái: "
        if "Lỗi" in text or "Cảnh báo" in text:
            prefix = "❌ "
            self.status_label.configure(text_color="#DC2626") 
        else:
            self.status_label.configure(text_color="#059669" if not is_working else "#2563EB")
            
        self.status_label.configure(text=f"{prefix}{text}")
        self.root.update()

    def log(self, text):
        timestamp = time.strftime("%H:%M:%S")
        self.log_box.insert("end", f"[{timestamp}] {text}\n")
        self.log_box.see("end")

    def choose_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.selected_file = file_path
            
            self.path_entry.configure(state="normal")
            self.path_entry.delete(0, "end")
            self.path_entry.insert(0, file_path)
            self.path_entry.configure(state="disabled")

            self.log(f"Đã nạp tệp tin: {file_path}")
            self.set_status(f"Đã chọn tệp: {file_path.split('/')[-1]}")

    def generate_keys(self):
        try:
            self.set_status("Đang sinh khóa RSA 2048-bit...", is_working=True)
            self.log("Bắt đầu khởi tạo cặp khóa RSA bất đối xứng...")

            public_key, private_key = RSAKeyGen.generate_keypair()
            RSAKeyGen.save_keys(public_key, private_key)

            self.log("Thành công: Đã lưu cấu hình khóa (public.key, private.key).")
            self.set_status("Sinh khóa hoàn tất.")
            messagebox.showinfo("Thành công", "Đã khởi tạo bộ khóa RSA thành công!")
        except Exception as e:
            self.log(f"Lỗi nghiêm trọng: {str(e)}")
            self.set_status("Lỗi trong quá trình sinh khóa.")
            messagebox.showerror("Lỗi Hệ Thống", str(e))

    def encrypt_file(self):
        if not self.selected_file:
            self.set_status("Lỗi: Chưa chọn tệp tin đầu vào.")
            messagebox.showwarning("Yêu cầu dữ liệu", "Vui lòng duyệt và chọn tệp tin cần mã hóa trước!")
            return
        try:
            self.set_status("Đang mã hóa dữ liệu với AES & RSA...", is_working=True)
            self.log(f"Đang tiến hành mã hóa tệp: {self.selected_file.split('/')[-1]}")

            result = HybridCrypto.encrypt_file(self.selected_file)

            self.log(f"Hoàn tất: Tệp tin đã được bảo mật. Xuất bản tại: {result}")
            self.set_status("Mã hóa thành công.")
            
            messagebox.showinfo(
                "Mã hóa thành công", 
                "Tệp tin của bạn đã được mã hóa an toàn!\n\n📌 Lưu ý: Để giải mã, vui lòng nhấn 'Duyệt Tệp...' và chọn lại file có đuôi .enc vừa được tạo."
            )
        except Exception as e:
            self.log(f"Lỗi mã hóa: {str(e)}")
            self.set_status("Thao tác mã hóa thất bại.")
            messagebox.showerror("Lỗi Mã Hóa", str(e))

    def decrypt_file(self):
        if not self.selected_file:
            self.set_status("Lỗi: Chưa chọn tệp tin đầu vào.")
            messagebox.showwarning("Yêu cầu dữ liệu", "Vui lòng duyệt và chọn tệp tin .enc cần giải mã trước!")
            return
        if not self.selected_file.endswith(".enc"):
            self.log("Cảnh báo: Định dạng tệp tin không hợp lệ (.enc).")
            reselect = messagebox.askyesno(
                "Phát hiện định dạng sai",
                "Tệp tin bạn đang chọn KHÔNG PHẢI là file mã hóa (không có đuôi .enc).\n\n"
                "Bạn có muốn hệ thống mở lại cửa sổ để chọn đúng file không?"
            )
            if reselect:
                self.choose_file()
                return
            else:
                self.log("Bỏ qua cảnh báo: Người dùng ép buộc giải mã định dạng lạ.")

        try:
            self.set_status("Đang giải mã và kiểm tra tính toàn vẹn (HMAC)...", is_working=True)
            self.log(f"Đang tiến hành giải mã tệp: {self.selected_file.split('/')[-1]}")

            result = HybridCrypto.decrypt_file(self.selected_file)

            self.log(f"Hoàn tất: Đã khôi phục dữ liệu gốc. Xuất bản tại: {result}")
            self.set_status("Giải mã thành công.")
            messagebox.showinfo("Thành công", "Dữ liệu đã được giải mã và khôi phục nguyên vẹn!")
        except Exception as e:
            self.log(f"Lỗi giải mã/xác thực: {str(e)}")
            self.set_status("Thao tác giải mã thất bại (Sai khóa hoặc dữ liệu hỏng).")
            messagebox.showerror("Lỗi Giải Mã", "Quá trình giải mã thất bại.\nDữ liệu có thể đã bị chỉnh sửa hoặc thiếu khóa hợp lệ.\n\nChi tiết: " + str(e))
