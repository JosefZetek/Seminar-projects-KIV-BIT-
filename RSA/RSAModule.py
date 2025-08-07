from tqdm import tqdm
from os import SEEK_END, SEEK_SET
import random
import math



class RSAModule:

    def __init__(self, p=None, q=None):
        self.number_of_rounds = 40
        self.input_length = 256
        self.output_length = 2048
        self.p = p if p is not None else self.__generate_key()
        self.q = q if q is not None else self.__generate_key()
        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)
        self.e = 65537
        self.d = pow(self.e, -1, self.phi)

    def export_public_key(self, filename):
        exported_file = open(filename, 'w')
        exported_file.write(f"e={hex(self.e)}\n")
        exported_file.write(f"n={hex(self.n)}\n")
        exported_file.close()

    def export_private_key(self, filename):
        exported_file = open(filename, 'w')
        exported_file.write(f"d={hex(self.d)}\n")
        exported_file.write(f"n={hex(self.n)}\n")
        exported_file.close()

    def import_public_key(self, filename):
        imported_file = open(filename, 'r')
        lines = imported_file.readlines()
        for line in lines:
            if line.startswith("e="):
                self.e = int(line.split('=')[1], 16)
            elif line.startswith("n="):
                self.n = int(line.split('=')[1], 16)
        imported_file.close()

    def import_private_key(self, filename):
        imported_file = open(filename, 'r')
        lines = imported_file.readlines()
        for line in lines:
            if line.startswith("d="):
                self.d = int(line.split('=')[1], 16)
            elif line.startswith("n="):
                self.n = int(line.split('=')[1], 16)
        imported_file.close()

    def encrypt_data(self, input_path, output_path):
        """
        Method fetches data, splits it into blocks and encrypts each block
        :param input_path: Path to input file (data to be encrypted)
        :param output_path: Path to output file (encrypted data)
        """

        input_file, output_file = open(input_path, "rb"), open(output_path, "wb")
        input_byte_length = (self.input_length // 8)

        data_length = self.__get_file_size(input_file)

        if data_length % input_byte_length != 0:
            raise ValueError(f"Data is expected to be padded to multiple of {input_byte_length} bytes")

        for _ in tqdm(range(int(data_length/input_byte_length))):

            current_data = bytearray(input_file.read(input_byte_length))
            encrypted_data = self.__encrypt(current_data)
            output_file.write(encrypted_data)

        input_file.close()
        output_file.close()

    def decrypt_data(self, input_path, output_path):
        """
        Method fetches data, splits it into blocks and decrypts each block
        :param input_path: Path to input file (data to be decrypted)
        :param output_path: Path to output file (decrypted data)
        """

        input_file, output_file = open(input_path, "rb"), open(output_path, "wb")
        output_byte_length = (self.output_length // 8)

        data_length = self.__get_file_size(input_file)

        if data_length % output_byte_length != 0:
            raise ValueError(f"Data is expected to be padded to multiple of {output_byte_length} bytes")

        for _ in tqdm(range(int(data_length/output_byte_length))):

            current_data = bytearray(input_file.read(output_byte_length))
            decrypted_data = self.__decrypt(current_data)
            output_file.write(decrypted_data)

        input_file.close()
        output_file.close()

    def __get_file_size(self, file):
        """
        Method returns size of the file
        :param file: File to get size of
        :return: Returns size of a file in bytes
        """

        file.seek(0, SEEK_END)
        data_length = file.tell()
        file.seek(0, SEEK_SET)

        return data_length

    def __encrypt(self, data: bytearray):
        """
        Method encrypts data using RSA algorithm
        :param data: Data to be encrypted
        :return: Returns encrypted data padded to 256 bytes
        """
        encrypted_data = pow(int.from_bytes(data, 'big'), self.e, self.n)
        return encrypted_data.to_bytes(self.output_length//8, 'big')

    def __decrypt(self, data):
        """
        Method decrypts data using RSA algorithm
        :param data: Data to be decrypted
        :return: Returns decrypted data
        """
        decrypted_data = int.from_bytes(data, 'big')
        decrypted_data = pow(decrypted_data, self.d, self.n)
        return int.to_bytes(decrypted_data, self.input_length//8, 'big')

    def __is_prime(self, n):
        """
        Method checks if number n is prime using Miller-Rabin primality test
        with trial division optimization
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

        rounds = min(40, 2 * int(math.log2(self.output_length)))

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

    def __generate_key(self):
        """
        Method generates random prime number with optimizations
        """

        key_size = self.output_length//2

        while True:
            candidate = random.getrandbits(key_size - 1)
            candidate = (candidate << 1) | 1  # Set LSB to 1 to make odd
            candidate |= (1 << (key_size - 1))  # Set MSB to 1

            if self.__is_prime(candidate):
                return candidate