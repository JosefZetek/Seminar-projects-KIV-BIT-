import os

from ImageFile import ImageFile
validation_folder = "validation/"
output_folder = "out/"
decoded_folder = "decoded/"

password = "bit2025"


def encode_test(input_name, extension, pass_phrase):

    try:
        input_image = open("weber.bmp", "rb")
    except Exception as e:
        print(f"Error opening file: weber.bmp \n {e}")
        return

    try:
        input_file = open(validation_folder + input_name + "." + extension, "rb")
    except Exception as e:
        print(f"Error with file: {validation_folder}{input_name}.{extension} \n {e}")
        input_image.close()
        return

    try:
        image = ImageFile(input_image, pass_phrase)
        image.encode_file(input_file, output_folder + input_name + "__weber.bmp")
    except Exception as e:
        print(f"Error with file: {input_file.name} \n {e}")

    input_image.close()
    input_file.close()



def decode_test(input_image, output_filename, pass_phrase):

    try:
        input_image = open(input_image, "rb")
    except Exception as e:
        print(f"Error with file: {input_image} \n {e}")
        return

    try:
        image = ImageFile(input_image, pass_phrase)
        image.decode_file(output_filename)
    except Exception as e:
        print(f"Error with file: {input_image.name} \n {e}")

    input_image.close()


def whole_test():
    #load files from directory and encode them
    for file in os.listdir(validation_folder):
        file_split = file.split(".")
        input_name = file_split[0]
        extension = file_split[1]
        encode_test(input_name, extension, password)

    # decode files from directory
    for file in os.listdir(output_folder):
        file_split = file.split("__")
        output_name = file_split[0]
        decode_test(output_folder + file, decoded_folder + output_name, password)

if __name__ == "__main__":
    whole_test()