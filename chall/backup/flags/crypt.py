import sys

from ecies import encrypt as enc, decrypt as dec
from coincurve import PrivateKey, PublicKey

def encrypt(keybytes: bytes, pt: bytes) -> bytes:
    pub = PublicKey.from_secret(keybytes)
    return enc(pub.format(True), pt)

def decrypt(keybytes: bytes, pt: bytes) -> bytes:
    priv = PrivateKey(keybytes)
    return dec(priv.secret, pt)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} keyfile source_file dest_file")
        exit(1)

    keyfile = sys.argv[1]
    with open(keyfile, "rb") as f:
        key = f.read()

    source_file = sys.argv[2]
    with open(source_file, "rb") as f:
        pt = f.read()

    ct = encrypt(key, pt)

    dest_file = sys.argv[3]
    with open(dest_file, "wb") as f:
        f.write(ct)

    exit(0)
