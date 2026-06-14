import random
from math import gcd


class RSACore:

    # ==========================
    # Lũy thừa modulo nhanh
    # ==========================
    @staticmethod
    def mod_exp(base, exp, mod):

        result = 1

        base %= mod

        while exp > 0:

            if exp & 1:
                result = (result * base) % mod

            exp >>= 1

            base = (base * base) % mod

        return result

    # ==========================
    # Miller Rabin
    # ==========================
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

    # ==========================
    # Sinh số nguyên tố
    # ==========================
    @staticmethod
    def generate_prime(bits):

        while True:

            p = random.getrandbits(bits)

            p |= (1 << bits - 1)
            p |= 1

            if RSACore.is_prime(p):
                return p

    # ==========================
    # Euclid mở rộng
    # ==========================
    @staticmethod
    def extended_gcd(a, b):

        if b == 0:
            return a, 1, 0

        g, x1, y1 = RSACore.extended_gcd(
            b,
            a % b
        )

        x = y1
        y = x1 - (a // b) * y1

        return g, x, y

    # ==========================
    # Nghịch đảo modulo
    # ==========================
    @staticmethod
    def mod_inverse(e, phi):

        g, x, _ = RSACore.extended_gcd(
            e,
            phi
        )

        if g != 1:
            raise Exception(
                "Không tồn tại nghịch đảo modulo"
            )

        return x % phi

    # ==========================
    # Sinh khóa RSA
    # ==========================
    @staticmethod
    def generate_keypair(bits=1024):

        p = RSACore.generate_prime(bits // 2)

        q = RSACore.generate_prime(bits // 2)

        while p == q:
            q = RSACore.generate_prime(bits // 2)

        n = p * q

        phi = (p - 1) * (q - 1)

        e = 65537

        while gcd(e, phi) != 1:
            e += 2

        d = RSACore.mod_inverse(
            e,
            phi
        )

        public_key = (e, n)

        private_key = (d, n)

        return public_key, private_key

    # ==========================
    # RSA Encrypt cho kieu bytes
    # ==========================
    @staticmethod
    def encrypt(message_bytes, public_key):

        e, n = public_key

        m = int.from_bytes(
            message_bytes,
            byteorder="big"
        )

        if m >= n:
            raise ValueError(
                "Message quá lớn"
            )

        c = RSACore.mod_exp(
            m,
            e,
            n
        )

        return c

    # ==========================
    # RSA Decrypt cho kieu byte
    # ==========================
    @staticmethod
    def decrypt(cipher_int, private_key):

        d, n = private_key

        m = RSACore.mod_exp(
            cipher_int,
            d,
            n
        )

        length = (m.bit_length() + 7) // 8

        return m.to_bytes(
            length,
            byteorder="big"
        )
    
    # ==========================
    # RSA encrypt cho kieu so nguyen
    # ==========================
    @staticmethod
    def encrypt_int(message_int, e, n):

        if message_int >= n:
            raise ValueError(
                "Message qua lon"
            )

        return RSACore.mod_exp(
            message_int,
            e,
            n
        )
    
    # ==========================
    # RSA decrypt cho kieu so nguyen
    # ==========================

    @staticmethod
    def decrypt_int(cipher_int, d, n):

        return RSACore.mod_exp(
            cipher_int,
            d,
            n
        )

