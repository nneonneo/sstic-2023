from ecpy.curves import Curve, Point
import hashlib
from dataclasses import dataclass
import ast
import sys
import baker_pubkey
from musig2_player import Hash_agg, Hash_non, Hash_sig, key_aggregation

cv = Curve.get_curve("secp256k1")
G = cv.generator
order = cv.order

exps = [int.from_bytes(hashlib.sha256(i.to_bytes(32,byteorder="big")).digest(),byteorder="big") for i in range(1, 4+1)]

@dataclass
class Message:
    msg: bytes
    sent_Rs: list[Point]
    recv_Rs: list[Point]
    sent_s: int
    recv_s: int

def parse_points(s: str) -> list[Point]:
    s = [int(c, 0) for c in s.split()]
    return [Point(s[i], s[i+1], cv) for i in range(0, 8, 2)]

chunks = open("../../chall/devices/deviceA/logs.txt").read().split("=====")
messages = []
for chunk in chunks:
    rows = [r.split(": ", 2)[2] for r in chunk.strip().split("\n")]
    messages.append(Message(
        ast.literal_eval(rows[1]),
        parse_points(rows[2]),
        parse_points(rows[3]),
        int(rows[4], 0),
        int(rows[5], 0),
    ))

def get_nonce_coeff(m, i):
    digest = int.from_bytes(hashlib.sha256(i.to_bytes(32,byteorder="big")).digest(),byteorder="big")
    m_int = int.from_bytes(m, "big")
    return pow(m_int, digest, order)

nb_players = 4
L = [baker_pubkey.MY_PK, baker_pubkey.BERTRAND_PK, baker_pubkey.CHARLES_PK, baker_pubkey.DANIEL_PK]
a = Hash_agg(L, baker_pubkey.MY_PK)

print("polys = [")
for m in messages:
    # first round
    nonce_coeffs = [get_nonce_coeff(m.msg, j+1) for j in range(nb_players)]
    # second round
    X = key_aggregation(L)
    b = Hash_non(X, m.recv_Rs, m.msg)

    R = Point.infinity()
    for j in range(len(L)):
        exp = pow(b, j, order)
        R += exp * m.recv_Rs[j]
    c = Hash_sig(X, R, m.msg)

    poly_coeffs = [(c * a) % order]
    for j in range(nb_players):
        poly_coeffs.append((nonce_coeffs[j] * pow(b,j,order)) % order)

    print(poly_coeffs, end=",\n")
print("]")

print("s =", [m.sent_s for m in messages])
