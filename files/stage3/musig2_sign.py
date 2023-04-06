import hashlib
from ecpy.curves import Curve, Point
from dataclasses import dataclass
import random
import sys

Point.__repr__ = lambda p: f"Point{p!s}"
cv = Curve.get_curve("secp256k1")
G = cv.generator
order = cv.order

@dataclass
class Key:
    pub: Point
    priv: int

def Hash_agg(L,X):
    to_hash = b""
    for i in L:
        to_hash += i.x.to_bytes(32,byteorder="big") + i.y.to_bytes(32,byteorder="big")
    to_hash += X.x.to_bytes(32,byteorder="big") + X.y.to_bytes(32,byteorder="big")
    return int.from_bytes(hashlib.sha256(to_hash).digest(),byteorder="big")

def Hash_non(X,Rs,m):
    to_hash = b""
    to_hash += X.x.to_bytes(32,byteorder="big") + X.y.to_bytes(32,byteorder="big")
    for i in Rs:
        to_hash += i.x.to_bytes(32,byteorder="big") + i.y.to_bytes(32,byteorder="big")
    to_hash += m
    return int.from_bytes(hashlib.sha256(to_hash).digest(),byteorder="big")

def Hash_sig(X,R,m):
    to_hash = b""
    to_hash += X.x.to_bytes(32,byteorder="big") + X.y.to_bytes(32,byteorder="big")
    to_hash += R.x.to_bytes(32,byteorder="big") + R.y.to_bytes(32,byteorder="big")
    to_hash += m
    return int.from_bytes(hashlib.sha256(to_hash).digest(),byteorder="big")

def key_aggregation(L):
    KeyAggCoef = [0] * len(L)
    Agg_Key = Point.infinity()
    for i in range(len(L)):
        KeyAggCoef[i] = Hash_agg(L,L[i])
        Agg_Key += KeyAggCoef[i] * L[i]
    return Agg_Key

def get_nonce(x,m,i):
    return random.randrange(order)

def first_sign_round_sign(x,m,nb_players,f_nonce):
    # each player draws a random number for each player
    bound = order
    rs = [0] * nb_players
    Rs = [0] * nb_players
    for j in range(nb_players):
        r = f_nonce(x,m,j+1)
        rs[j] = r
        Rs[j] = (r * G) 
    return rs, Rs

def second_sign_round_sign(nb_players, b, c, a, x, rs):
    s = (c * a * x) % order
    for j in range(nb_players):
        s = (s + rs[j] * pow(b,j,order)) % order
    return s

def musig2_sign(m: bytes, keys: list[Key]):
    nb_players = len(keys)

    L = [key.pub for key in keys]
    a_s = [Hash_agg(L, key.pub) for key in keys]
    pub_agg = key_aggregation(L)

    # Sign1
    rss = []
    Rss = []
    for pi in range(nb_players):
        my_rs, my_Rs = first_sign_round_sign(keys[pi].priv,m,4,get_nonce)
        rss.append(my_rs)
        Rss.append(my_Rs)

    # Sign1Agg
    Rs = [sum((Rss[i][j] for i in range(nb_players)), Point.infinity()) for j in range(nb_players)]

    # Sign2
    b = Hash_non(pub_agg,Rs,m)

    R = Point.infinity()
    for j in range(nb_players):
        exp = pow(b,j,order)
        R += exp* Rs[j]
    c = Hash_sig(pub_agg,R,m)

    ss = []
    for pi in range(nb_players):
        my_s = second_sign_round_sign(nb_players, b, c, a_s[pi], keys[pi].priv, rss[pi])
        ss.append(my_s)

    # Sign2Agg
    s = sum(ss) % order

    return pub_agg, (R, s)

def musig2_verify(m: bytes, pub_agg: Point, signature: (Point, int)) -> bool:
    R, s = signature
    c = Hash_sig(pub_agg, R, m)
    return (s*G) == R+(c*pub_agg)

m = sys.argv[1].encode()

# test parameters
keys = [
    Key(pub=Point(0xb6704cb462c0871913c59740b6940dd26974c0597d063130fa3f5bed28980cb2, 0x9aae6cc9d9c21495d488630ba6159a5abac4222817b0126c50c2b4536e6ee398, cv), priv=83946478759348520629356546897287872656112391590446743294955578116072481018298),
    Key(pub=Point(0x947c83005ac7f0cbc2fe1d13ec18ab2e0b8114bdcdcc47292562fe63c7ecaf20, 0x285f7ef6a521ac5c03848dfe9e1e7eabbb22f4cec71c637dbe3563fac370d2bb, cv), priv=49226462498534414321988481446447571367989069176036022880878458700447405068098),
    Key(pub=Point(0x59688a7c19ce5f40c8d42c3f7a9c11288ec3edebbeb0023dfb8fb50295b3889b, 0x5023d939ea399352f66f8d870e38b5590d77eab093fedc09eb5a31d0db2708c6, cv), priv=47695572360867323752057745507308325637508830466529069378814753499917103895016),
    Key(pub=Point(0x1a25185fc81a14d17fa332cf05da9906116c103312548acba9765c972b65f0d8, 0xc35ad24cdd6c7e058a462158774456340de5e9838010b2a5b086a9d679d1b0e2, cv), priv=42912087803455266243515357720379189396041829591093178754210177864293815810651)
]
assert all(key.priv * G == key.pub for key in keys)
pub_agg, signature = musig2_sign(m, keys)
valid = musig2_verify(m, pub_agg, signature)
assert valid

# real parameters
keys = [
    Key(pub=Point(0x7d29a75d7745c317aee84f38d0bddbf7eb1c91b7dcf45eab28d6d31584e00dd0, 0x25bb44e5ab9501e784a6f31a93c30cd6ad5b323f669b0af0ca52b8c5aa6258b9, cv), priv=32397748964588217353341318317432783880090649436123362081161843221664749742056),
    Key(pub=Point(0x206aeb643e2fe72452ef6929049d09496d7252a87e9daf6bf2e58914b55f3a90, 0x46c220ee7cbe03b138a76dcb4db673c35e2ab81b4235486fe4dbd2ad093e8df4, cv), priv=0x81e8d3a6ad341da46e6361b7c1c376b5423e7ad04748077b93a0c20263305824),
    Key(pub=Point(0xab44fe53836d50fa4b5755aa0683b5a61726e508a1ca814a93e1eab7122abdea, 0x4cbd1496aa36fc016bfe7b12c9fb8bb78eacab6f3655c586604250bb870cdaf1, cv), priv=0x04c6cb31e7f3ba694cc01f50d6573f8d22be2e1bd7861e176d5b4ed43c13f9f9),
    Key(pub=Point(0xb1c1e7545483dce5567345a7cf12d1c0a6bcbd0637b81f4082453a9bd89bd701, 0xb01d4cadf75b8ce3e05eda73a81a7c5cfb67618950e60657d61d4a44d2115dc7, cv), priv=0x54644250491642f996d1c94a4ac8a8dbec66dd0ba66f0271b4e65d5570026a9b)
]
assert all(key.priv * G == key.pub for key in keys)
pub_agg, signature = musig2_sign(m, keys)
assert musig2_verify(m, pub_agg, signature)
print(f"{signature[0].x:x} {signature[0].y:x} {signature[1]:x}", valid)
assert valid
