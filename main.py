import tkinter as tk

from application import HybridCryptoGUI


def main():

    root = tk.Tk()

    app = HybridCryptoGUI(root)

    root.mainloop()


if __name__ == "__main__":
    main()