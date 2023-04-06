from starkware.crypto.signature.fast_pedersen_hash import pedersen_hash
import random

'''
- (a << 128) + b = hash2(hash2(hash2(nonce, code[0]), code[1]), code[2])
    - Could add a fourth element to make sure the hash fits in 236 bits (2^16 chance)
- `id_hash = hash2(nonce, id)`
- `code = [id_hash * id_hash, 0x1336 / (code[0] * 0x1337), 0x208b7fff7fff7ffe / id_hash]`
- nonce = 121485921437276981477059375547635758552
- prime = 0x800000000000011000000000000000000000000000000000000000000000001
'''

hash2 = pedersen_hash
nonce = 121485921437276981477059375547635758552
prime = 0x800000000000011000000000000000000000000000000000000000000000001
id = random.getrandbits(128)
id_hash = hash2(nonce, id)
code = [None] * 4
code[0] = pow(id_hash, 2, prime)
code[1] = 0x1336 * pow(code[0] * 0x1337, -1, prime) % prime
code[2] = 0x208b7fff7fff7ffe * pow(id_hash, -1, prime) % prime
h = hash2(hash2(hash2(nonce, code[0]), code[1]), code[2])
for i in range(10000000):
    if i % 100 == 0: print("...", i)
    code[3] = random.getrandbits(128)
    h2 = hash2(h, code[3])
    if h2 < (1<<236):
        break

print("%x" % id)
print(",".join(["%x" % c for c in code]))
print("%x" % (h2 >> 128))
print("%x" % (h2 & ((1<<128)-1)))

