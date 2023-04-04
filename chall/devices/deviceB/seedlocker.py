#!/bin/env python3
import sys
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins
from bip_utils.utils.mnemonic import Mnemonic


class G:
    def __init__(self, data):
        self.kind = int.from_bytes(data.read(4), "little")
        if self.kind == 3:
            self.a = int.from_bytes(data.read(4), "little")
        elif self.kind in (4, 5):
            self.a = int.from_bytes(data.read(4), "little")
            self.na = int.from_bytes(data.read(1), "little")
            self.b = int.from_bytes(data.read(4), "little")
            self.nb = int.from_bytes(data.read(1), "little")
        elif self.kind == 6:
            self.a = int.from_bytes(data.read(4), "little")
            self.b = int.from_bytes(data.read(4), "little")
            self.n = int.from_bytes(data.read(1), "little")
        elif self.kind == 7:
            self.a = int.from_bytes(data.read(4), "little")
        elif self.kind == 8:
            self.a = int.from_bytes(data.read(4), "little")
            self.b = int.from_bytes(data.read(4), "little")
            self.c = int.from_bytes(data.read(4), "little")
        elif self.kind == 9:
            self.dff = int.from_bytes(data.read(1), "little")
            self.a = int.from_bytes(data.read(4), "little")
            self.n = int.from_bytes(data.read(1), "little")
        self.tstamp = 0
        self.value = 0


def b(data):
    size = int.from_bytes(data.read(8), "little")
    res = []
    for i in range(size):
        res.append(int.from_bytes(data.read(4), "little"))
    return res


class E:
    def __init__(self):
        data = open("seed.bin", "rb")
        size = int.from_bytes(data.read(8), "little")
        self.gs = []
        self.dffs = []
        for i in range(size):
            g = G(data)
            self.gs.append(g)
            if g.kind == 9:
                self.dffs.append(i)
        self.key = b(data)
        self.good = [int.from_bytes(data.read(4), "little")]
        self.data = b(data)
        self.cycles = 1

    def get(self, i):
        g = self.gs[i]
        if g.tstamp < self.cycles:
            if g.kind == 0:
                res = 0
            elif g.kind == 1:
                res = 1
            elif g.kind == 2:
                res = g.value
            elif g.kind == 3:
                res = self.get(g.a)
            elif g.kind == 4:
                res = (self.get(g.a) ^ g.na) & (self.get(g.b) ^ g.nb)
            elif g.kind == 5:
                res = (self.get(g.a) ^ g.na) | (self.get(g.b) ^ g.nb)
            elif g.kind == 6:
                res = self.get(g.a) ^ self.get(g.b) ^ g.n
            elif g.kind == 7:
                res = int(not self.get(g.a))
            elif g.kind == 8:
                if self.get(g.c):
                    res = self.get(g.b)
                else:
                    res = self.get(g.a)
            elif g.kind == 9:
                res = g.dff ^ g.n
            g.value = res
            g.tstamp = self.cycles
        return g.value

    def set_uint(self, b, value):
        for i in b:
            g = self.gs[i]
            assert g.kind == 2
            g.value = value & 1
            value >>= 1

    def get_uint(self, b):
        res = 0
        for i in b[::-1]:
            res = (res << 1) | self.get(i)
        return res

    def step(self):
        for i in self.dffs:
            self.get(i)
        for i in self.dffs:
            self.gs[i].dff = self.get(self.gs[i].a)
        self.cycles += 1


password = bytes.fromhex(sys.argv[1])
e = E()

for b in password:
    for i in range(4):
        key = (b >> (i * 2)) & 3
        e.set_uint(e.key, key)
        for _ in range(2):
            e.step()

if e.get_uint(e.good) == 1:
    data = e.get_uint(e.data).to_bytes(len(e.data) // 8, "little").decode()
    print(f"Seed: {data}")
    seed_bytes = Bip39SeedGenerator(Mnemonic.FromString(data)).Generate()
    key = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM)
    priv = key.PrivateKey()
    pub = key.PublicKey()
    print(f"Private key: 0x{priv.Raw().ToHex()}")
    print(f"Public key X: 0x{pub.m_pub_key.Point().X():x}")
    print(f"Public key Y: 0x{pub.m_pub_key.Point().Y():x}")
else:
    print("Wrong password")
