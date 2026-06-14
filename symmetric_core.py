import os
import hmac
import hashlib

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from rsa_core import RSACore
from rsa_keygen import RSAKeyGen


class HybridCrypto:

    AES_BLOCK = 16
    # padding truoc khi ma hoa
    @staticmethod
    def pad(data):

        pad_len = 16 - len(data) % 16

        return data + bytes([pad_len]) * pad_len

    #xoa phan padding di sau giai ma

    @staticmethod
    def unpad(data):

        pad_len = data[-1]
        if pad_len<1 or pad_len>16:
            raise ValueError("Padding ko hop le")

        return data[:-pad_len]

    # ma hoa file bang rsa lai

    @staticmethod
    def encrypt_file(input_file):
        
        #kiem tra su ton tai cua file
        if not os.path.exists(input_file):
            raise FileNotFoundError("khong tim thay file")
        
        e, n = RSAKeyGen.load_public_key()

        session_key = get_random_bytes(32)

        #doc du lieu tu file
        with open(input_file, "rb") as f:
            plaintext = f.read()

        plaintext = HybridCrypto.pad(
            plaintext
        )
        
        # sinh iv 
        iv = get_random_bytes(16)
        
        # khoi tao aes-cbc

        aes = AES.new(
            session_key,
            AES.MODE_CBC,
            iv
        )

        ciphertext = aes.encrypt(
            plaintext
        )

        #kiem tra tinh toan ven du lieu
        mac = hmac.new(
            session_key,
            iv + ciphertext,
            hashlib.sha256
        ).digest()
        
        session_int = int.from_bytes(
            session_key,
            "big"
        )
        
        #ma hoa khoa aes bang rsa
        encrypted_session = RSACore.encrypt_int(
            session_int,
            e,
            n
        )

        rsa_bytes = (n.bit_length() + 7) // 8

        encrypted_session = (
            encrypted_session.to_bytes(
                rsa_bytes,
                "big"
            )
        )

        output_file = input_file + ".enc"

        with open(output_file, "wb") as f:

            f.write(encrypted_session)
            f.write(iv)
            f.write(mac)
            f.write(ciphertext)

        return output_file

    # giai ma file

    @staticmethod
    def decrypt_file(enc_file):

        # kiem tra file ton tai ko
        if not os.path.exists(enc_file):
            raise FileNotFoundError(
                "khong tim thay file"
            )
        
        d, n = RSAKeyGen.load_private_key()

        rsa_bytes = (
            n.bit_length() + 7
        ) // 8

        with open(enc_file, "rb") as f:

            # doc khoa aes da ma hoa
            encrypted_session = f.read(
                rsa_bytes
            )

            iv = f.read(16)

            mac=f.read(32)

            ciphertext = f.read()

        encrypted_int = int.from_bytes(
            encrypted_session,
            "big"
        )

        # giai ma khoa aes bang rsa
        
        session_int = RSACore.decrypt_int(
            encrypted_int,
            d,
            n
        )

        session_key = session_int.to_bytes(
            32,
            "big"
        )

        # tinh lai hmac
        expected_mac= hmac.new(
            session_key,
            iv + ciphertext,
            hashlib.sha256
        ).digest()

        # kiem tra tinh toan ven du lieu

        if not hmac.compare_digest(
            mac,
            expected_mac
        ):
            raise ValueError(
                "du lieu da bi chinh sua!"
            )
        

        aes = AES.new(
            session_key,
            AES.MODE_CBC,
            iv
        )
        
        # giai ma du lieu

        plaintext = aes.decrypt(
            ciphertext
        )

        plaintext = HybridCrypto.unpad(
            plaintext
        )

        output_file = (
            enc_file.replace(
                ".enc",
                "_recovered"
            )
        )

        with open(output_file, "wb") as f:
            f.write(plaintext)

        return output_file