import customtkinter as ctk
from application import ModernHybridCryptoGUI

def main():
    root = ctk.CTk()
    
    app = ModernHybridCryptoGUI(root)
    
    root.mainloop()

if __name__ == "__main__":
    main()
