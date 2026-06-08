import os

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from rsa_core import RSACore
from rsa_keygen import RSAKeyGen


class HybridCrypto:

    AES_BLOCK = 16

    @staticmethod
    def pad(data):

        pad_len = 16 - len(data) % 16

        return data + bytes([pad_len]) * pad_len

    @staticmethod
    def unpad(data):

        pad_len = data[-1]

        return data[:-pad_len]

    @staticmethod
    def encrypt_file(input_file):

        e, n = RSAKeyGen.load_public_key()

        session_key = get_random_bytes(32)

        with open(input_file, "rb") as f:
            plaintext = f.read()

        plaintext = HybridCrypto.pad(
            plaintext
        )

        iv = get_random_bytes(16)

        aes = AES.new(
            session_key,
            AES.MODE_CBC,
            iv
        )

        ciphertext = aes.encrypt(
            plaintext
        )

        session_int = int.from_bytes(
            session_key,
            "big"
        )

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
            f.write(ciphertext)

        return output_file

    @staticmethod
    def decrypt_file(enc_file):

        d, n = RSAKeyGen.load_private_key()

        rsa_bytes = (
            n.bit_length() + 7
        ) // 8

        with open(enc_file, "rb") as f:

            encrypted_session = f.read(
                rsa_bytes
            )

            iv = f.read(16)

            ciphertext = f.read()

        encrypted_int = int.from_bytes(
            encrypted_session,
            "big"
        )

        session_int = RSACore.decrypt_int(
            encrypted_int,
            d,
            n
        )

        session_key = session_int.to_bytes(
            32,
            "big"
        )

        aes = AES.new(
            session_key,
            AES.MODE_CBC,
            iv
        )

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