from RSAModule import RSAModule
import sys
import os

def check_file_exists(file_path):
    return os.path.isfile(file_path)

def fetch_arguments():
    if len(sys.argv) != 3:
        print("Usage: python3 rsa.py <-e/-d> <file>")
        sys.exit(1)

    operation_mode, file_path = sys.argv[1], sys.argv[2]

    if operation_mode not in ['-e', '-d']:
        print("Invalid mode. Use -e for encryption or -d for decryption.")
        sys.exit(1)

    if not check_file_exists(file_path):
        print(f"File {file_path} not found.")
        sys.exit(1)

    return operation_mode, file_path


def get_filename(path):
    return os.path.basename(path)

def get_extension(filename):
    return filename.split('.')[-1] if '.' in filename else ''

def remove_extension(filename):
    return os.path.splitext(filename)[0]


if __name__ == "__main__":
    mode, file_path = fetch_arguments()
    script_folder = os.getcwd()  # Save encrypted files in the script's directory
    filename = get_filename(file_path)
    filebase = remove_extension(filename)
    file_extension = get_extension(filename)
    rsa = RSAModule()

    if mode == '-e':
        rsa.encrypt_data(file_path, os.path.join(script_folder, filebase + "_" + file_extension + ".rsa"))

        rsa.export_public_key(os.path.join(script_folder, "pub_key.txt"))
        rsa.export_private_key(os.path.join(script_folder, "priv_key.txt"))
        print("Encryption complete.")

    elif mode == '-d':
        public_key_path = os.path.join(script_folder, "pub_key.txt")
        private_key_path = os.path.join(script_folder, "priv_key.txt")

        input_path = os.path.join(script_folder, filename)

        if not check_file_exists(public_key_path):
            print(f"Public key file {public_key_path} not found. Please encrypt a file first.")
            sys.exit(1)

        if not check_file_exists(private_key_path):
            print(f"Private key file {private_key_path} not found. Please encrypt a file first.")
            sys.exit(1)

        #LOAD PUBLIC KEY
        try:
            rsa.import_public_key(public_key_path)
        except:
            print(f"Public key file {public_key_path} is corrupted or invalid.")
            sys.exit(1)

        # LOAD PRIVATE KEY
        try:
            rsa.import_private_key(private_key_path)
        except:
            print(f"Private key file {private_key_path} is corrupted or invalid.")
            sys.exit(1)

        if filename.endswith(".rsa"):
            file_extension = filebase.split("_")[-1]
            filebase = filebase.replace("_" + file_extension, "")
            output_path = os.path.join(script_folder, filebase + "." + file_extension)
            try:
                rsa.decrypt_data(input_path, output_path)
            except:
                print("Decryption ECB failed. The file might be corrupted or the key is incorrect.")
                sys.exit(1)
        else:
            print("Unknown encrypted file format.")
            sys.exit(1)

        print("Decryption complete.")