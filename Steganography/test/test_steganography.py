import subprocess
import unittest
import os

# pip install opencv-python if not installed
import cv2


STEGANOGRAPHY_IMG = "../weber.bmp"
DATA_SOURCE = "../validation/"
OUTPUT_DIR = "../out/"
DECODED_DIR = "../decoded/"

class SteganographyTester(unittest.TestCase):

    def test_steganography_img_sizes(self):
        """
        This test compares the size of the STEGANOGRAPHY_IMG with all size in OUTPUT_DIR
        """

        steg_file_stats = os.stat(STEGANOGRAPHY_IMG)
        # get size in bytes
        steg_img_file_size = steg_file_stats.st_size

        for file in sorted(os.listdir(OUTPUT_DIR)):
            filename = os.path.join(OUTPUT_DIR, file)
            file_stats = os.stat(filename)
            assert file_stats.st_size == steg_img_file_size


    def test_all_imgs_after_steganography(self):
        """
        This test checks if all files in OUTPUT_DIR are different from the STEGANOGRAPHY_IMG
        """
        with open(STEGANOGRAPHY_IMG, "rb") as fr:
            original_img_bytes = fr.read()

        for file in sorted(os.listdir(OUTPUT_DIR)):
            filename = os.path.join(OUTPUT_DIR, file)

            # let's check if we can open this image with opencv
            img = cv2.imread(filename)
            assert img.size != 0
            assert True == cv2.haveImageReader(filename)

            # image in OUTPUT_DIR should be altered, so it must be different from the original image
            # let's compare first 1024 Bytes
            with open(filename, "rb") as fr:
                img_bytes = fr.read()
            assert original_img_bytes[:1024] != img_bytes[:1024]


    def test_decoded_results(self):
        """
        This test compares all files in DATA_SOURCE contra all files in DECODED_DIR
        """

        for decoded_file in sorted(os.listdir(DECODED_DIR)):
            decoded_filename = os.path.join(DECODED_DIR, decoded_file)
            for validation_file in sorted(os.listdir(DATA_SOURCE)):
                validation_filename = os.path.join(DATA_SOURCE, validation_file)
                if decoded_file == validation_file:
                    # check if files are identical
                    with open(decoded_filename, "rb") as fr:
                        decoded_bytes = fr.read()

                    with open(validation_filename, "rb") as fr:
                        validation_bytes = fr.read()
                    print(f"Comparing {validation_filename} and {decoded_filename}")
                    assert decoded_bytes == validation_bytes
                    print("OK")
                    break



