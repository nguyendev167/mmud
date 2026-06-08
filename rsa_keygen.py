import random
from math import gcd

from rsa_core import RSACore


class RSAKeyGen:

    @staticmethod
    def is_prime(n, k=20):

        if n < 2:
            return False

        if n in (2, 3):
            return True

        if n % 2 == 0:
            return False

        r = 0
        d = n - 1

        while d % 2 == 0:
            r += 1
            d //= 2

        for _ in range(k):

            a = random.randint(2, n - 2)

            x = pow(a, d, n)

            if x == 1 or x == n - 1:
                continue

            for _ in range(r - 1):

                x = pow(x, 2, n)

                if x == n - 1:
                    break
            else:
                return False

        return True

    @staticmethod
    def generate_prime(bits):

        while True:

            p = random.getrandbits(bits)

            p |= (1 << bits - 1)
            p |= 1

            if RSAKeyGen.is_prime(p):
                return p

    @staticmethod
    def generate_keypair(bits=2048):

        p = RSAKeyGen.generate_prime(bits // 2)
        q = RSAKeyGen.generate_prime(bits // 2)

        while p == q:
            q = RSAKeyGen.generate_prime(bits // 2)

        n = p * q

        phi = (p - 1) * (q - 1)

        e = 65537

        while gcd(e, phi) != 1:
            e += 2

        d = RSACore.mod_inverse(
            e,
            phi
        )

        return (e, n), (d, n)

    @staticmethod
    def save_keys(public_key, private_key):

        with open("public.key", "w") as f:
            f.write(
                f"{public_key[0]}\n{public_key[1]}"
            )

        with open("private.key", "w") as f:
            f.write(
                f"{private_key[0]}\n{private_key[1]}"
            )

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