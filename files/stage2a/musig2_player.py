#import musig2_comm
#import my_secret_data
import baker_pubkey
import hashlib
from ecpy.curves import Curve, Point

cv = Curve.get_curve("secp256k1")
G = cv.generator
order = cv.order

#private key
#my_privkey = my_secret_data.privkey

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

def get_nonce(x,m,i):
    # NOTE: this is deterministic but we shouldn't sign twice the same message, so we are fine 
    digest = int.from_bytes(hashlib.sha256(i.to_bytes(32,byteorder="big")).digest(),byteorder="big")
    m_int = int.from_bytes(m, "big")
    return pow(x*m_int, digest, order)

def key_aggregation(L):
    KeyAggCoef = [0] * len(L)
    Agg_Key = Point.infinity()
    for i in range(len(L)):
        KeyAggCoef[i] = Hash_agg(L,L[i])
        Agg_Key += KeyAggCoef[i] * L[i]
    return Agg_Key

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

def second_sign_round_sign(L, Rs, m, a, x, rs):
    X = key_aggregation(L)
    b = Hash_non(X,Rs,m)

    R = Point.infinity()
    for j in range(len(L)):
        exp = pow(b,j,order)
        R += exp* Rs[j]
    R = R
    c = Hash_sig(X,R,m)

    s = (c * a * x) % order
    for j in range(nb_players):
        s = (s + rs[j] * pow(b,j,order)) % order
    return R, s, c

if __name__ == "__main__":    
    nb_players = 4

    # my public key
    my_pubkey = Point(0x7d29a75d7745c317aee84f38d0bddbf7eb1c91b7dcf45eab28d6d31584e00dd0, 0x25bb44e5ab9501e784a6f31a93c30cd6ad5b323f669b0af0ca52b8c5aa6258b9)    
    Bob_pubkey = baker_pubkey.BOB_PK
    Charlie_pubkey = baker_pubkey.CHARLIE_PK
    Dany_pubkey = baker_pubkey.DANY_PK

    L = [my_pubkey, Bob_pubkey, Charlie_pubkey, Dany_pubkey]
    
    a = Hash_agg(L,my_pubkey)
    # receive the message to sign
    m = musig2_comm.receive_message_to_sign(log=True) #input
    
    # compute the first round signature
    my_rs, my_Rs = first_sign_round_sign(my_privkey,m,4,get_nonce)
    
    # send my_Rs to the aggregator
    musig2_comm.send_to_aggregator(my_Rs, log=True)

    # aggregator answers with the aggregation of Rs
    Rs = musig2_comm.receive_from_aggregator()
    
    # compute my signature share
    my_s = second_sign_round_sign(L, Rs, m, a, my_privkey, my_rs)
    
    # send it to the aggregator
    musig2_comm.send_to_aggregator(my_s, log=True)

    # receive the final signature
    s = musig2_comm.receive_from_aggregator(log=True)
