from AESModule import AESModule
import sys
import os


def check_file_exists(file_path):
    return os.path.isfile(file_path)

def fetch_arguments():
    if len(sys.argv) != 3:
        print("Usage: python3 main.py <-e/-d> <file>")
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


def remove_extension(filename):
    return os.path.splitext(filename)[0]


if __name__ == "__main__":
    mode, file_path = fetch_arguments()
    script_folder = os.getcwd()  # Save encrypted files in the script's directory
    filename = get_filename(file_path)
    file_base = remove_extension(filename)
    aes = AESModule()

    if mode == '-e':
        aes.encrypt_data_ecb(file_path, os.path.join(script_folder, file_base + ".aes"))
        aes.encrypt_data_cbc(file_path, os.path.join(script_folder, file_base + "_cbc.aes"))
        aes.encrypt_data_cfb(file_path, os.path.join(script_folder, file_base + "_cfb.aes"))
        aes.export_key(os.path.join(script_folder, "aes_key.txt"))
        print("Encryption complete.")

    elif mode == '-d':
        key_path = os.path.join(script_folder, "aes_key.txt")
        input_path = os.path.join(script_folder, filename)

        if not check_file_exists(key_path):
            print(f"Key file {key_path} not found. Please encrypt a file first.")
            sys.exit(1)

        try:
            aes.import_key(key_path)
        except Exception:
            print(f"Key file {key_path} is corrupted or invalid.")
            sys.exit(1)

        if filename.endswith("_cbc.aes"):
            output_path = os.path.join(script_folder, file_base.replace("_cbc", "") + ".csv")
            try:
                aes.decrypt_data_cbc(input_path, output_path)
            except:
                print("Decryption CBC failed. The file might be corrupted or the key is incorrect.")
                sys.exit(1)

        elif filename.endswith("_cfb.aes"):
            output_path = os.path.join(script_folder, file_base.replace("_cfb", "") + ".csv")
            try:
                aes.decrypt_data_cfb(input_path, output_path)
            except:
                print("Decryption CFB failed. The file might be corrupted or the key is incorrect.")
                sys.exit(1)

        elif filename.endswith(".aes"):
            output_path = os.path.join(script_folder, file_base + ".csv")
            try:
                aes.decrypt_data_ecb(input_path, output_path)
            except:
                print("Decryption ECB failed. The file might be corrupted or the key is incorrect.")
                sys.exit(1)
        else:
            print("Unknown encrypted file format.")
            sys.exit(1)

        print("Decryption complete.")