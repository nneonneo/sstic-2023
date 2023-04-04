import hashlib

NB_ZEROS = 6

#banner = input("Banner:").encode()

def solve_pow(banner):
    number = 0
    while True:
        m = hashlib.sha256()
        number += 1

        m.update(str(number).encode() + banner)

        digest = m.hexdigest().encode()
        if digest[:NB_ZEROS] == b"0" * NB_ZEROS:
            print (F"Solution: input {str(number).encode()} sha256({str(number).encode()} + {banner}) = {digest}")
            return str(number).encode()