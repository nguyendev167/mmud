import random
from math import gcd

from rsa_core import RSACore


class RSAKeyGen:

    @staticmethod
    def generate_keypair(bits=2048):
        return RSACore.generate_keypair(bits)

    @staticmethod
    def save_keys(public_key, private_key):
        with open("public.key", "w") as f:
            f.write(
                f"{public_key[0]}\n{public_key[1]}")
        with open("private.key", "w") as f:
            f.write(
                f"{private_key[0]}\n{private_key[1]}")

    @staticmethod
    def load_public_key():
        with open("public.key", "r") as f:
            e = int(f.readline())
            n = int(f.readline())
        return e, n

    @staticmethod
    def load_private_key():
        with open("private.key", "r") as f:
            d = int(f.readline())
            n = int(f.readline())
        return d, n