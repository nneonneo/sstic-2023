from config import MUSIG2_PUBKEY
import hashlib

from ecpy.curves import Curve, Point

secp256k1 = Curve.get_curve("secp256k1")

def Hash_sig(X: Point, R: Point, m: bytes) -> int:
    to_hash = b""
    to_hash += X.x.to_bytes(32, "big") + X.y.to_bytes(32, "big")
    to_hash += R.x.to_bytes(32, "big") + R.y.to_bytes(32, "big")
    to_hash += m
    return int.from_bytes(hashlib.sha256(to_hash).digest(), "big")

def verify(message: str, signature: ((int, int), int)) -> bool:
    try:
        R, s = signature

        G = secp256k1.generator
        X = Point(*MUSIG2_PUBKEY, secp256k1)
        R = Point(*R, secp256k1)

        c = Hash_sig(X, R, message.encode())
    except:
        return False

    return (s*G) == R+(c*X)
