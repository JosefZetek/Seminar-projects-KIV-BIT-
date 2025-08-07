from DigitalSignature import DigitalSignature

if __name__ == '__main__':
    valid_student_number = b"A22B0202P"
    invalid_student_number = b"A22B0202"

    digital_signature = DigitalSignature("x.txt", "y.txt", "g.txt", "p.txt")
    digital_signature.sign(valid_student_number)

    verification_of_valid_data = digital_signature.verify_signature(valid_student_number, "signature.txt")
    verification_of_invalid_data = digital_signature.verify_signature(invalid_student_number, "signature.txt")

    print(f"Ověření digitálního podpisu pro platné osobní číslo: {verification_of_valid_data}")
    print(f"Ověření digitálního podpisu pro neplatné osobní číslo: {verification_of_invalid_data}")