from os import SEEK_END, SEEK_SET
import numpy as np
from tqdm import tqdm

class AESModule:


    def __init__(self, key:bytes=None):
        """
        Constructor for AESModule class
        :param key: Key used for AES algorithm (if None, a random key will be generated)
        """

        np.set_printoptions(formatter={'int': hex})
        self.dimension = 4
        self.block_size = self.dimension ** 2

        self.sbox = self.__get_sbox()
        self.inv_sbox = self.__get_inv_sbox()
        self.rcon = self.__get_rcon()
        self.mix_columns_matrix = self.__get_mix_columns_matrix()
        self.inv_mix_columns_matrix = self.__get_inv_mix_columns_matrix()

        self.keys = self.__key_expansion(key)
        self.initialization_vector = b"ABCDEFGHIJKLMNOP"

    def encrypt_data_ecb(self, input_path, output_path):
        """
        Method encrypts data using ECB mode
        :param input_path: Path to input file (data to be encrypted)
        :param output_path: Path to output file (encrypted data)
        """

        input_file, output_file = open(input_path, "rb"), open(output_path, "wb")

        data_length = self.__get_file_size(input_file)

        if data_length % self.block_size != 0:
            raise ValueError(f"Data is expected to be padded to multiple of {self.block_size} bytes")

        for _ in tqdm(range(int(data_length/self.block_size))):

            current_data = input_file.read(self.block_size)

            current_block = self.__convert_data_to_block(current_data)
            current_block = self.__encrypt(current_block)
            encrypted_data = self.__convert_block_to_data(current_block)
            output_file.write(encrypted_data)

        input_file.close()
        output_file.close()

    def decrypt_data_ecb(self, input_path, output_path):
        """
        Method decrypts data using ECB mode
        :param input_path: Path to input file (encrypted data)
        :param output_path: Path to output file (decrypted data)
        """

        input_file, output_file = open(input_path, "rb"), open(output_path, "wb")

        data_length = self.__get_file_size(input_file)

        if data_length % self.block_size != 0:
            raise ValueError(f"Data is expected to be padded to multiple of {self.block_size} bytes")

        for _ in tqdm(range(int(data_length/self.block_size))):
            current_data = input_file.read(self.block_size)

            current_block = self.__convert_data_to_block(current_data)
            current_block = self.__decrypt(current_block)
            decrypted_data = self.__convert_block_to_data(current_block)
            output_file.write(decrypted_data)

        input_file.close()
        output_file.close()

    def encrypt_data_cbc(self, input_path, output_path):
        """
        Method encrypts data using CBC mode
        :param input_path: Path to input file (data to be encrypted)
        :param output_path: Path to output file (encrypted data)
        """

        input_file, output_file = open(input_path, "rb"), open(output_path, "wb")

        data_length = self.__get_file_size(input_file)

        if data_length % self.block_size != 0:
            raise ValueError(f"Data is expected to be padded to multiple of {self.block_size} bytes")

        previous_block = self.__convert_data_to_block(self.initialization_vector)

        for _ in tqdm(range(int(data_length/self.block_size))):
            current_data = input_file.read(self.block_size)
            current_block = self.__convert_data_to_block(current_data) ^ previous_block
            current_block = self.__encrypt(current_block)
            encrypted_data = self.__convert_block_to_data(current_block)
            output_file.write(encrypted_data)
            previous_block = current_block

        input_file.close()
        output_file.close()

    def decrypt_data_cbc(self, input_path, output_path):
        """
        Method decrypts data using CBC mode
        :param input_path: Path to input file (encrypted data)
        :param output_path: Path to output file (decrypted data)
        """

        input_file, output_file = open(input_path, "rb"), open(output_path, "wb")

        data_length = self.__get_file_size(input_file)

        if data_length % self.block_size != 0:
            raise ValueError(f"Data is expected to be padded to multiple of {self.block_size} bytes")

        previous_block = self.__convert_data_to_block(self.initialization_vector)

        for _ in tqdm(range(int(data_length/self.block_size))):
            current_data = input_file.read(self.block_size)
            current_block = self.__convert_data_to_block(current_data)
            decrypted_data = self.__decrypt(current_block) ^ previous_block
            decrypted_data = self.__convert_block_to_data(decrypted_data)
            output_file.write(decrypted_data)
            previous_block = current_block

        input_file.close()
        output_file.close()

    def encrypt_data_cfb(self, input_path, output_path):
        """
        Method encrypts data using CFB mode
        :param input_path: Path to input file (data to be encrypted)
        :param output_path: Path to output file (encrypted data)
        """

        input_file, output_file = open(input_path, "rb"), open(output_path, "wb")

        data_length = self.__get_file_size(input_file)

        if data_length % self.block_size != 0:
            raise ValueError(f"Data is expected to be padded to multiple of {self.block_size} bytes")

        previous_block = self.__convert_data_to_block(self.initialization_vector)

        for _ in tqdm(range(int(data_length/self.block_size))):
            current_data = input_file.read(self.block_size)
            current_block = self.__convert_data_to_block(current_data)
            encrypted_data = self.__encrypt(previous_block) ^ current_block
            output_data = self.__convert_block_to_data(encrypted_data)
            output_file.write(output_data)
            previous_block = encrypted_data

        input_file.close()
        output_file.close()

    def decrypt_data_cfb(self, input_path, output_path):
        """
        Method decrypts data using CFB mode
        :param input_path: Path to input file (encrypted data)
        :param output_path: Path to output file (decrypted data)
        """

        input_file, output_file = open(input_path, "rb"), open(output_path, "wb")

        data_length = self.__get_file_size(input_file)

        if data_length % self.block_size != 0:
            raise ValueError(f"Data is expected to be padded to multiple of {self.block_size} bytes")

        previous_block = self.__convert_data_to_block(self.initialization_vector)

        for _ in tqdm(range(int(data_length/self.block_size))):
            current_data = input_file.read(self.block_size)
            current_block = self.__convert_data_to_block(current_data)
            decrypted_data = self.__encrypt(previous_block) ^ current_block
            output_data = self.__convert_block_to_data(decrypted_data)
            output_file.write(output_data)
            previous_block = current_block

        input_file.close()
        output_file.close()

    def import_key(self, input_path):
        """
        Method imports key from a file
        :param input_path: Path to input file (key)
        """
        file = open(input_path, "r")
        hex_key = file.read().strip()
        file.close()
        self.keys = self.__key_expansion(bytes.fromhex(hex_key))

    def export_key(self, output_path):
        """
        Method exports key to a file
        :param output_path: Path to output file (key)
        """
        file = open(output_path, "w")
        key = self.__convert_block_to_data(self.keys[0])
        hex_key = key.hex()
        file.write(hex_key)
        file.close()


    def __encrypt(self, data):
        """
        Performs basic AES encryption for a given block of data
        :param data: 2D numpy array with data to be encrypted
        :return: Returns 2D numpy array with encrypted data
        """
        current_block = self.__add_round_key(data, self.keys[0])

        for i in range(1, 10):
            current_block = self.__sub_bytes(current_block)
            current_block = self.__shift_rows(current_block)
            current_block = self.__mix_columns(current_block)
            current_block = self.__add_round_key(current_block, self.keys[i])

        current_block = self.__sub_bytes(current_block)
        current_block = self.__shift_rows(current_block)
        current_block = self.__add_round_key(current_block, self.keys[10])

        return current_block

    def __decrypt(self, data):
        """
        Performs basic AES decryption for a given block of data
        :param data: 2D numpy array with data to be decrypted
        :return: Returns 2D numpy array with decrypted data
        """

        input = self.__add_round_key(data, self.keys[10])

        for i in range(1, 10):
            input = self.__inv_shift_rows(input)
            input = self.__inv_sub_bytes(input)
            input = self.__add_round_key(input, self.keys[10 - i])
            input = self.__inv_mix_columns(input)

        input = self.__inv_sub_bytes(input)
        input = self.__inv_shift_rows(input)
        input = self.__add_round_key(input, self.keys[0])

        return input

    def __generate_key(self):
        """
        Method generates a random key for AES algorithm
        :return: Returns 2D numpy array with random values (key)
        """
        min_number = 0
        max_number = 256
        return np.random.randint(min_number, max_number, (self.dimension, self.dimension))

    def __sub_bytes(self, state):
        """
        Method substitutes bytes in the state using S-box
        :param state: 2D numpy array with values to be substituted (this state isn't modified)
        :return: Returns 2D numpy array with substituted values
        """

        new_state = np.zeros(state.shape, dtype=int)

        if state.ndim == 1:
            for i in range(state.shape[0]):
                new_state[i] = self.__substitute_byte(state[i])

        elif state.ndim == 2:
            for i in range(state.shape[0]):
                for j in range(state.shape[1]):
                    new_state[i][j] = self.__substitute_byte(state[i][j])

        return new_state

    def __inv_sub_bytes(self, state):
        """
        Method reverses changes made by __sub_bytes method
        :param state: 2D numpy array with values to be substituted (this state isn't modified)
        :return: Returns 2D numpy array with substituted values
        """

        new_state = np.zeros(state.shape, dtype=int)

        if state.ndim == 1:
            for i in range(state.shape[0]):
                new_state[i] = self.__inv_substitute_byte(state[i])

        elif state.ndim == 2:
            for i in range(state.shape[0]):
                for j in range(state.shape[1]):
                    new_state[i][j] = self.__inv_substitute_byte(state[i][j])

        return new_state


    def __shift_rows(self, state):
        """
        Method shifts rows in a state
        :param state: 2D numpy array with values to be shifted (this state isn't modified)
        :return: Returns 2D numpy array with shifted values
        """

        new_state = np.zeros(state.shape, dtype=int)

        for i in range(0, state.shape[0]):
            new_state[i] = np.roll(state[i], -i)

        return new_state

    def __inv_shift_rows(self, state):
        """
        Method reverses changes made by __shift_rows method
        :param state: 2D numpy array with values to be shifted (this state isn't modified)
        :return: Returns 2D numpy array with shifted values
        """

        rotation_index_start = 1

        for i in range(rotation_index_start, self.dimension):
            state[i] = np.roll(state[i], i)

        return state

    def __mix_columns(self, state):
        """
        Method mixes columns in a state
        :param state: 2D numpy array with values to be mixed (this state isn't modified)
        :return: Returns 2D numpy array with mixed values
        """
        result = np.zeros((self.dimension, self.dimension), dtype=int)

        for i in range(self.dimension):
            for j in range(self.dimension):
                for k in range(self.dimension):
                    result[i][j] = self.__add(result[i][j], self.__multiply(self.mix_columns_matrix[i][k], state[k][j]))
        return result

    def __inv_mix_columns(self, state):
        """
        Method reverses changes made by __mix_columns method
        :param state: 2D numpy array with values to be mixed (this state isn't modified)
        :return: Returns 2D numpy array with mixed values
        """

        result = np.zeros((self.dimension, self.dimension), dtype=int)

        for i in range(self.dimension):
            for j in range(self.dimension):
                for k in range(self.dimension):
                    result[i][j] = self.__add(result[i][j], self.__multiply(self.inv_mix_columns_matrix[i][k], state[k][j]))
        return result

    def __add_round_key(self, state, round_key):
        """
        Method adds round key to the state
        :param state: 2D numpy array that round key will be added to
        :param round_key: 2D numpy array that will be added to the state
        :return: Returns 2D numpy array with added round key (XOR)
        """

        return state ^ round_key

    def __key_expansion(self, key):
        """
        Method expands the key to 11 keys (10 rounds + 1 initial key)
        :param key: 2D numpy array
        :return: Returns numpy array with expanded keys
        """

        key = self.__generate_key() if key is None else self.__convert_data_to_block(key)

        keys = [key]

        for i in range(10):
            previous_key = keys[i]
            new_key = np.zeros((self.dimension, self.dimension), dtype=int)

            for j in range(self.dimension):
                if j == 0:
                    column = previous_key[:, 3]
                    column = self.__rotate_column(column)
                    column = self.__sub_bytes(column)
                    column = column ^ self.rcon[i] ^ previous_key[:, j]
                else:
                    column = previous_key[:, j]
                    column = column ^ new_key[:, j - 1]

                new_key[:, j] = column

            keys.append(new_key)

        return np.array(keys)

    def __get_sbox(self):
        """
        Method returns S-box used in AES algorithm
        :return: Method returns 2D numpy array with S-box values
        """

        return np.array([
            [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
            [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
            [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
            [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
            [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
            [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
            [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
            [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
            [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
            [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
            [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
            [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
            [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
            [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
            [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
            [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]
        ])

    def __get_inv_sbox(self):
        """
        Method returns inverse S-box used in AES algorithm
        :return: Returns 2D numpy array with inverse S-box values
        """

        return np.array([
            [0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB],
            [0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB],
            [0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E],
            [0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25],
            [0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92],
            [0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84],
            [0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06],
            [0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B],
            [0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73],
            [0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E],
            [0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B],
            [0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4],
            [0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F],
            [0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF],
            [0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61],
            [0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D]
        ])

    def __get_rcon(self):
        """
        Method returns Rcon used in AES algorithm
        :return: Returns 2D numpy array with Rcon values
        """

        return np.array([
            [0x01, 0x00, 0x00, 0x00],
            [0x02, 0x00, 0x00, 0x00],
            [0x04, 0x00, 0x00, 0x00],
            [0x08, 0x00, 0x00, 0x00],
            [0x10, 0x00, 0x00, 0x00],
            [0x20, 0x00, 0x00, 0x00],
            [0x40, 0x00, 0x00, 0x00],
            [0x80, 0x00, 0x00, 0x00],
            [0x1B, 0x00, 0x00, 0x00],
            [0x36, 0x00, 0x00, 0x00]
        ])

    def __get_mix_columns_matrix(self):
        """
        Method returns MixColumns matrix used in AES algorithm
        :return: Returns 2D numpy array with MixColumns matrix values
        """

        return np.array([
            [0x02, 0x03, 0x01, 0x01],
            [0x01, 0x02, 0x03, 0x01],
            [0x01, 0x01, 0x02, 0x03],
            [0x03, 0x01, 0x01, 0x02]
        ])

    def __get_inv_mix_columns_matrix(self):
        """
        Method returns inverse MixColumns matrix used in AES algorithm
        :return: Returns 2D numpy array with inverse MixColumns matrix values
        """

        return np.array([
            [0x0E, 0x0B, 0x0D, 0x09],
            [0x09, 0x0E, 0x0B, 0x0D],
            [0x0D, 0x09, 0x0E, 0x0B],
            [0x0B, 0x0D, 0x09, 0x0E]
        ])

    def __multiply(self, a, b):
        """
        Method multiplies two numbers in Galois field GF(2^8)
        :param a: First number to be multiplied
        :param b: Second number to be multiplied
        :return:  Returns result of multiplication
        """

        reduction_polynomial = 0x11B
        highest_value = 0xFF
        lsb_mask = 1

        result = 0
        while b:
            if b & lsb_mask:
                result ^= a

            b >>= 1
            a <<= 1

            if a > highest_value:
                a ^= reduction_polynomial
        return result

    def __add(self, a, b):
        """
        Method adds two numbers in Galois field GF(2^8)
        :param a: First number to be added
        :param b: Second number to be added
        :return: Returns result of addition
        """

        return a ^ b

    def __rotate_column(self, column):
        """
        Method rotates column in a state
        :param column: Numpy array with values to be rotated
        :return: Returns numpy array with rotated values
        """

        return np.roll(column, -1)

    def __substitute_byte(self, value):
        """
        Method substitutes byte using S-box
        :param value: Value to be substituted
        :return: Returns substituted value
        """

        row_mask, column_mask = 0xF0, 0x0F
        shift_right = 4

        row = (value & row_mask) >> shift_right
        column = value & column_mask
        return self.sbox[row][column]

    def __inv_substitute_byte(self, value):
        """
        Method reverses changes made by __substitute_byte method
        :param value: Value to be substituted
        :return: Returns substituted value
        """

        row_mask, column_mask = 0xF0, 0x0F
        shift_right = 4

        row = (value & row_mask) >> shift_right
        column = value & column_mask
        return self.inv_sbox[row][column]

    def __convert_data_to_block(self, data):
        """
        Method converts data (bytes array) to block (2D numpy array)
        :param data: Bytes array to be converted
        :return: Returns 2D numpy array with converted values
        """

        i, j = 0, 0

        if len(data) != self.block_size:
            raise ValueError(f"Data is expected to be padded to multiple of {self.block_size} bytes")

        block = np.zeros((self.dimension, self.dimension), dtype=int)
        for byte in data:
            if i >= self.dimension:
                break
            if j >= self.dimension:
                i += 1
                j = 0
            block[j][i] = byte
            j += 1

        return block

    def __convert_block_to_data(self, block):
        """
        Method converts block (2D numpy array) to data (bytes array)
        :param block: 2D numpy array to be converted
        :return: Returns bytes array
        """

        data = bytearray()

        for j in range(block.shape[1]):
            for i in range(block.shape[0]):
                data.append(block[i][j])

        return bytes(data)

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



