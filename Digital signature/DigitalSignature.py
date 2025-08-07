import random
import math
import hashlib
import re
import os

class DigitalSignature:

    def __init__(self, file_path_x=None, file_path_y=None, file_path_g=None, file_path_p=None):
        """
        Constructor initializing the parameters
        for the Digital signature using ELGamal algorithm
        """
        self.key_length = 512

        self.__load_keys(file_path_x, file_path_y, file_path_g, file_path_p)

        if self.p is None or self.y is None or self.g is None or self.x is None:
            self.p, q = self.__generate_safe_prime()
            self.g = self.__find_primitive_root(self.p, q)

            # Soukromý klíč x (1 < x < p-1)
            self.x = random.randint(2, self.p - 2)

            # Veřejný klíč y = g^x mod p
            self.y = pow(self.g, self.x, self.p)

            self.__export_key("x.txt", self.x)
            self.__export_key("y.txt", self.y)
            self.__export_key("g.txt", self.g)
            self.__export_key("p.txt", self.p)


    def sign(self, data):
        """
        Method signs the hash value h using the private key x
        :param h: Hash value to be signed
        :return: Returns the signature (r, s)
        """
        h = self.__hash_data(data)
        while True:
            k = random.randint(2, self.p - 2)
            if self.__gcd(k, self.p - 1) == 1:
                break

        r = pow(self.g, k, self.p)

        k_inv = pow(k, -1, self.p - 1)
        s = (k_inv * (h - self.x * r)) % (self.p - 1)

        self.__export_signature(r, s)

    def verify_signature(self, data, file_path_signature):
        """
        Method verifies the signature (r, s) of the hash value h
        :param h: Hash value to be verified
        :param r: R component of the signature
        :param s: S component of the signature
        :return: Returns True if the signature is valid, False otherwise
        """

        h = self.__hash_data(data)
        r, s = self.__import_signature(file_path_signature)

        if r is None or s is None:
            return False

        left = (pow(self.y, r, self.p) * pow(r, s, self.p)) % self.p
        right = pow(self.g, h, self.p)
        return left == right

    def __load_keys(self, file_path_x, file_path_y, file_path_g, file_path_p):
        """
        Method loads the keys from the files
        :param file_path_x: Path to the private key file
        :param file_path_y: Path to the y parameter file
        :param file_path_g: Path to the g parameter file
        :param file_path_p: Path to the p parameter file
        """
        self.x = self.__import_key(file_path_x)
        self.y = self.__import_key(file_path_y)
        self.g = self.__import_key(file_path_g)
        self.p = self.__import_key(file_path_p)


    def __export_signature(self, r, s):
        """
        Method exports the signature to a file
        :param r: R component of the signature
        :param s: S component of the signature
        """
        file = open("signature.txt", 'w')
        file.write(f"r={r}\ns={s}")
        file.close()

    def __import_signature(self, file_path_signature):
        """
        Method imports the signature from a file
        :param file_path_signature: Path to the signature file
        :return: Returns the signature (r, s)
        """
        if not self.__check_file_exists(file_path_signature):
            return None, None

        imported_file = open(file_path_signature, 'r')
        lines = imported_file.readlines()
        imported_file.close()

        if len(lines) == 0:
            return None

        r, s = None, None

        for line in lines:
            if not re.match(r'.*[0-9a-fA-F]+.*', line.strip()):
                continue

            if line.startswith("r="):
                r = int(line[2:])

            if line.startswith("s="):
                s = int(line[2:])

        return r, s

    def __export_key(self, filename, key):
        """
        Method exports the key to a file
        :param filename: Name of the file
        :param key: Key to be exported
        """
        file = open(filename, 'w')
        file.write(hex(key))
        file.close()


    def __import_key(self, filename):
        """
        Import private key
        :param filename: Name of a file
        :return: Returns the key as an integer or None if failed
        """

        if not self.__check_file_exists(filename):
            return None

        imported_file = open(filename, 'r')
        lines = imported_file.readlines()
        imported_file.close()

        if len(lines) == 0:
            return None

        for line in lines:
            if not re.match(r'.*[0-9a-fA-F]+.*', line.strip()):
                continue

            return int(line, 16)

        return None

    def __check_file_exists(self, file_path):
        if file_path is None:
            return False
        return os.path.isfile(file_path)

    def __hash_data(self, data):
        """
        Hashes the input data using SHA-256
        :param data: Data to be hashed
        :return: Returns the hash value as an integer
        """
        h = hashlib.sha256(data).hexdigest()
        return int(h, 16)

    def __gcd(self, a, b):
        """
        Method calculates the greatest common divisor of a and b
        :param a: Number a
        :param b: Number b
        :return: Returns the greatest common divisor of a and b
        """
        while b:
            a, b = b, a % b
        return a

    def __generate_safe_prime(self):
        """
        Generates a safe prime p
        such that p = 2q + 1 and both p and q are prime
        :return: Returns the safe prime p and its corresponding q
        """
        while True:
            q = self.__generate_prime()
            p = 2 * q + 1
            if self.__is_prime(p):
                return p, q

    def __find_primitive_root(self, p, q):
        """
        Finds a primitive root g modulo p
        :param p: Parameter p
        :param q: Parameter q
        :return: Returns the primitive root g
        """
        for g in range(2, p):
            if pow(g, 2, p) != 1 and pow(g, q, p) != 1:
                return g
        raise ValueError("No primitive root found")

    def __is_prime(self, n):
        """
        Method checks if number n is prime using Miller-Rabin primality test
        with trial division optimization
        :param n: Number to be checked
        :return: Returns True if n is prime, False otherwise
        """
        # Check small primes and obvious cases
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n % 2 == 0:
            return False

        # Try division by first few primes
        small_primes = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53]
        for prime in small_primes:
            if n % prime == 0:
                return n == prime

        # Miller-Rabin test
        r, d = 0, n - 1
        while d % 2 == 0:
            d //= 2
            r += 1

        rounds = min(40, 2 * int(math.log2(self.key_length)))

        for _ in range(rounds):
            a = random.randrange(2, n - 1)
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

    def __generate_prime(self):
       """
       Method generates random prime number with optimizations
       :return: Returns a prime number
       """
       while True:
           candidate = random.getrandbits(self.key_length - 1)
           candidate = (candidate << 1) | 1  # Set LSB to 1 to make odd
           candidate |= (1 << (self.key_length - 1))  # Set MSB to 1
           if self.__is_prime(candidate):
               return candidate

