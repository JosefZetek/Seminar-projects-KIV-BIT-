import constants
import hashlib

from io import SEEK_END

class ImageFile:

    def __init__(self, input_image, pass_phrase):
        """
        Method initializes the ImageFile, checks
        format of the passed file and sets frequently used variables.
        :param input_image: File to be used as a base for encoding/decoding
        """
        self.input_image = input_image

        if not self.__check_format():
            raise ValueError("Invalid image format")

        self.data_offset = self.__get_data_offset()
        self.width, self.height = self.__get_dimensions()
        self.padding = self.__get_padding()
        self.capacity = self.__get_image_capacity()
        self.hash = self.__get_hash(pass_phrase)

    def encode_file(self, input_file, output_filename):
        """
        Encodes file with the given name to the image file
        :param input_file: Input file to be encoded
        :param output_filename: Output file to be written to
        """


        file_size = self.__get_file_size(input_file)

        if self.capacity < (file_size + constants.INTEGER_SIZE + constants.EXTENSION_SIZE):
            raise ValueError(f"File is too large to be encoded.")

        current_width, current_height = 0, 0

        try:
            output_image = open(output_filename, "wb")
        except Exception as e:
            raise ValueError(f"Failed opening file: {e}")



        self.__copy_image_metadata(output_image)
        current_width, current_height = self.__write_file_size(file_size, output_image, current_width, current_height)
        current_width, current_height = self.__write_extension(input_file, output_image, current_width, current_height)
        current_width, current_height = self.__write_contents(input_file, file_size, output_image, current_width, current_height)
        self.__copy_rest_of_image(output_image, current_width, current_height)
        output_image.close()

    def decode_file(self, output_filename):
        """
        Method decodes the file from the image
        :param output_filename: Name of a file where the decoded file will be written
        """

        current_width, current_height = 0, 0

        # If the input image is too small to fit metadata
        if self.capacity < (constants.INTEGER_SIZE + constants.EXTENSION_SIZE):
            raise ValueError("File size is too small to contain any data.")

        file_size, current_width, current_height = self.__fetch_file_size(current_width, current_height)

        # If the file is too large
        if self.capacity < (file_size + constants.INTEGER_SIZE + constants.EXTENSION_SIZE):
            raise ValueError("File size to fetch loaded file size.")

        file_extension, current_width, current_height = self.__fetch_file_extension(current_width, current_height)
        file_contents, current_width, current_height = self.__fetch_file_content(file_size, current_width, current_height)

        try:
            output_file = open(output_filename + "." + file_extension, "wb")
        except Exception as e:
            raise ValueError(f"Failed opening file: {e}")

        output_file.write(file_contents)
        output_file.close()

    def __write_contents(self, file, file_size, output_image, current_width, current_height):
        """
        Method encodes the contents of the file to the output image
        :param file: Source to be encoded
        :param file_size: Size of the source file (or size to be encoded)
        :param output_image: File to write the encoded data to
        :param current_width: Current width position
        :param current_height: Current height position
        :return: Returns the current width and height positions
        """

        file.seek(0)
        self.__seek_file(current_width, current_height)
        self.__seek_file(current_width, current_height, output_image)

        hash_index = 0

        while file.tell() < file_size:
            byte = file.read(1)[0]

            byte ^= self.hash[hash_index]
            hash_index = (hash_index + 1) % len(self.hash)

            bit_index = 7

            while bit_index >= 0:
                bit = (byte >> bit_index) & 1
                self.__write_bit(bit, output_image)

                bit_index -= 1
                current_width += 1

                if current_width >= self.width:
                    current_width = 0
                    current_height += 1

                    if current_height >= self.height:
                        break

                    self.__seek_file(current_width, current_height)
                    self.__seek_file(current_width, current_height, output_image)


        return current_width, current_height

    def __write_file_size(self, file_size, output_image, width_position, height_position):
        """
        Method writes the size of the file to the output image as 4 byte unsigned integer, little endian format
        :param file_size: File size to be written
        :param output_image: File to write the size to
        :param width_position: Current width position
        :param height_position: Current height position
        :return: Returns the current width and height positions after encoding the size
        """

        self.__seek_file(width_position, height_position)
        self.__seek_file(width_position, height_position, output_image)

        size_bytes = file_size.to_bytes(constants.INTEGER_SIZE, "little")

        for size_byte in size_bytes:
            bit_index = 7

            while bit_index >= 0:
                bit = (size_byte >> bit_index) & 1
                self.__write_bit(bit, output_image)

                bit_index -= 1
                width_position += 1

                if width_position >= self.width:
                    width_position = 0
                    height_position += 1

                    if height_position >= self.height:
                        break

                    self.__seek_file(width_position, height_position)
                    self.__seek_file(width_position, height_position, output_image)

        return width_position, height_position

    def __write_extension(self, input_file, output_image, current_width, current_height):
        """
        Method writes the extension of the file to the output image
        :param input_file: Input file
        :param output_image: Output file
        :param current_width: Current width position
        :param current_height: Current height position
        """

        self.__seek_file(current_width, current_height)
        self.__seek_file(current_width, current_height, output_image)

        extension_bytes = self.__get_file_extension_bytes(input_file)

        for extension_byte in extension_bytes:
            bit_index = 7

            while bit_index >= 0:
                bit = (extension_byte >> bit_index) & 1
                self.__write_bit(bit, output_image)

                bit_index -= 1
                current_width += 1

                if current_width >= self.width:
                    current_width = 0
                    current_height += 1

                    if current_height >= self.height:
                        break

                    self.__seek_file(current_width, current_height)
                    self.__seek_file(current_width, current_height, output_image)

        return current_width, current_height


    def __copy_image_metadata(self, output_image):
        """
        Method copies metadata from the input image to the output image
        :param output_image: File to write metadata to
        """
        self.__copy_image_data(output_image, 0, self.data_offset)

    def __copy_rest_of_image(self, output_image, current_width, current_height):
        """
        Method copies data from current position all the way to the end of the image
        :param output_image: File to write data to
        :param current_width: Current width position
        :param current_height: Current height position
        """
        start = self.data_offset + current_height * (self.width + self.padding) + current_width
        end = self.data_offset + self.height * (self.width + self.padding)
        self.__copy_image_data(output_image, start, end)

    def __copy_image_data(self, output_image, start, end):
        """
        Method copies data from the input image to the output image
        :param output_image: file to write data to
        :param start: start position in the input image
        :param end: end position in the input image
        """
        self.input_image.seek(start)
        output_image.seek(start)

        remaining = end - start
        while remaining > 0:
            to_read = min(constants.BUFFER_SIZE, remaining)
            data = self.input_image.read(to_read)

            if not data:
                break

            output_image.write(data)
            remaining -= len(data)

    def __seek_file(self, width_position, height_position, file=None):
        """"
        Method seeks to the position in the image file
        :param width_position: Width position
        :param height_position: Height position
        :param file: File to seek in
        """
        if file is None:
            file = self.input_image

        seek_pos = self.data_offset + height_position * (self.width + self.padding) + width_position
        file.seek(seek_pos)

    def __write_bit(self, bit: int, file):
        """
        Writes a single bit to a file
        :param bit: Bit to be written
        :param file: File to write the bit to
        """
        byte = self.input_image.read(1)[0]
        byte = (byte & 0xFE) | (bit & 1)
        file.write(bytes([byte]))

    def __read_bit(self):
        byte = self.input_image.read(1)[0]
        return byte & 1

    def __check_format(self):
        """
        Method checks if the file has same size as declared in the header
        :return: Returns True if the file has correct format, False otherwise
        """

        size = self.__get_file_size(self.input_image)
        if size < (constants.SIZE_OFFSET + constants.INTEGER_SIZE):
            return False

        self.input_image.seek(constants.SIZE_OFFSET)
        declared_size = int.from_bytes(self.input_image.read(constants.INTEGER_SIZE), "little")

        return size == declared_size

    def __get_padding(self):
        """
        Method calculates the padding in each row of the image
        :return: Returns number of bytes of padding for each row
        """
        return (constants.PADDING_MULTIPLE - ((self.width * constants.BYTES_PER_PIXEL) % constants.PADDING_MULTIPLE)) % constants.PADDING_MULTIPLE

    def __get_hash(self, pass_phrase):
        """
        Method calculates the hash from the passphrase
        :param pass_phrase: Phrase to use for encoding/decoding
        :return: Returns the hash of the passphrase as sequence of bytes
        """
        return hashlib.sha512(pass_phrase.encode()).digest()

    def __get_file_extension_bytes(self, file):
        """
        Method fetches the extension of the file passed
        :param file: File to fetch the extension from
        :return: Returns the extension as a sequence of bytes padded with zeros to 4 bytes
        """
        file_split = file.name.split(".")
        extension = "" if len(file_split) < 2 else file_split[-1]

        extension_bytes = extension.encode('ascii')
        result = bytearray(constants.EXTENSION_SIZE)

        for i in range(min(len(extension_bytes), constants.EXTENSION_SIZE)):
            result[i] = extension_bytes[i]

        return bytes(result)

    def __get_file_size(self, file):
        """
        Method fetches the size of the file
        Keeps the current position in the file
        :param file: File to fetch the size from
        :return: Returns the size of the file
        """
        current_pos = file.tell()
        file.seek(0, SEEK_END)
        size = file.tell()
        file.seek(current_pos)
        return size

    def __get_image_capacity(self):
        """
        Method calculates the image's capacity in bytes (space for encoding additional data).
        :return: image capacity in bytes
        """
        return self.width * self.height / constants.BITS_IN_BYTE

    def __get_data_offset(self):
        """
        Method fetches where the image data starts
        in the file from image header
        :return: Returns the offset in bytes
        """
        self.input_image.seek(constants.DATA_OFFSET)
        return int.from_bytes(self.input_image.read(constants.INTEGER_SIZE), "little")

    def __get_dimensions(self):
        """
        Method fetches the image's dimensions
        from the image header
        :return: Returns width and height of the image
        """
        self.input_image.seek(constants.DIMENSIONS_OFFSET)
        width = int.from_bytes(self.input_image.read(constants.INTEGER_SIZE), "little")
        height = int.from_bytes(self.input_image.read(constants.INTEGER_SIZE), "little")
        return width * constants.BYTES_PER_PIXEL, height

    def __fetch_file_size(self, current_width, current_height):
        """
        Method fetches the size of the file from the image bytes at given position
        :param current_width: Current width position
        :param current_height: Current height position
        :return: Returns file_size, current_width, current_height (position after fetching the size)
        """
        self.__seek_file(current_width, current_height)

        file_size_bytes = []

        for i in range(constants.INTEGER_SIZE):

            bit_index = constants.BITS_IN_BYTE - 1
            current_byte = 0

            while bit_index >= 0:

                current_byte |= self.__read_bit() << bit_index

                bit_index -= 1
                current_width += 1

                if current_width >= self.width:
                    current_width = 0
                    current_height += 1

                    if current_height >= self.height:
                        break

                    self.__seek_file(current_width, current_height)

            file_size_bytes.append(current_byte)

        file_size = int.from_bytes(file_size_bytes, "little")
        return file_size, current_width, current_height

    def __fetch_file_extension(self, current_width, current_height):
        """
        Method fetches file extension at current position
        :param current_width: Current width position
        :param current_height: Current height position
        :return: Returns file extension, current_width, current_height (position after fetching the extension)
        """
        self.__seek_file(current_width, current_height)

        file_extension_bytes = []

        for i in range(constants.INTEGER_SIZE):

            bit_index = constants.BITS_IN_BYTE - 1
            current_byte = 0

            while bit_index >= 0:

                current_byte |= self.__read_bit() << bit_index

                bit_index -= 1
                current_width += 1

                if current_width >= self.width:
                    current_width = 0
                    current_height += 1

                    if current_height >= self.height:
                        break

                    self.__seek_file(current_width, current_height)

            file_extension_bytes.append(current_byte)

        raw_string = bytes(file_extension_bytes).decode('utf-8', errors='replace')
        extension = ''.join(char for char in raw_string if char.isprintable())
        return extension, current_width, current_height

    def __fetch_file_content(self, file_size, current_width, current_height):
        """
        Method fetches the content of a file from the image
        :param file_size: Size of the file to be fetched
        :param current_width: Current width position
        :param current_height: Current height position
        :return: Returns bytes (content), current_width, current_height (position after fetching the content)
        """
        self.__seek_file(current_width, current_height)

        content_bytes = []
        hash_index = 0

        for i in range(file_size):

            bit_index = constants.BITS_IN_BYTE - 1
            current_byte = 0

            while bit_index >= 0:

                current_byte |= self.__read_bit() << bit_index

                bit_index -= 1
                current_width += 1

                if current_width >= self.width:
                    current_width = 0
                    current_height += 1

                    if current_height >= self.height:
                        break

                    self.__seek_file(current_width, current_height)

            current_byte ^= self.hash[hash_index]
            hash_index = (hash_index + 1) % len(self.hash)

            content_bytes.append(current_byte)

        return bytes(content_bytes), current_width, current_height