#!/bin/env python3
import sys
from z3 import *

class G:
    def __init__(self, data):
        self.kind = int.from_bytes(data.read(4), "little")
        if self.kind == 3:
            self.a = int.from_bytes(data.read(4), "little")
        elif self.kind in (4, 5):
            self.a = int.from_bytes(data.read(4), "little")
            self.na = BoolVal(bool(int.from_bytes(data.read(1), "little")))
            self.b = int.from_bytes(data.read(4), "little")
            self.nb = BoolVal(bool(int.from_bytes(data.read(1), "little")))
        elif self.kind == 6:
            self.a = int.from_bytes(data.read(4), "little")
            self.b = int.from_bytes(data.read(4), "little")
            self.n = BoolVal(bool(int.from_bytes(data.read(1), "little")))
        elif self.kind == 7:
            self.a = int.from_bytes(data.read(4), "little")
        elif self.kind == 8:
            self.a = int.from_bytes(data.read(4), "little")
            self.b = int.from_bytes(data.read(4), "little")
            self.c = int.from_bytes(data.read(4), "little")
        elif self.kind == 9:
            self.dff = BoolVal(bool(int.from_bytes(data.read(1), "little")))
            self.a = int.from_bytes(data.read(4), "little")
            self.n = BoolVal(bool(int.from_bytes(data.read(1), "little")))
        self.tstamp = 0
        self.value = BoolVal(False)

def b(data):
    size = int.from_bytes(data.read(8), "little")
    res = []
    for i in range(size):
        res.append(int.from_bytes(data.read(4), "little"))
    return res


class E:
    def __init__(self):
        data = open("../../chall/devices/deviceB/seed.bin", "rb")
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
                res = BoolVal(False)
            elif g.kind == 1:
                res = BoolVal(True)
            elif g.kind == 2:
                res = g.value
            elif g.kind == 3:
                res = self.get(g.a)
            elif g.kind == 4:
                res = And(Xor(self.get(g.a), g.na), Xor(self.get(g.b), g.nb))
            elif g.kind == 5:
                res = Or(Xor(self.get(g.a), g.na), Xor(self.get(g.b), g.nb))
            elif g.kind == 6:
                res = Xor(Xor(self.get(g.a), self.get(g.b)), g.n)
            elif g.kind == 7:
                res = Not(self.get(g.a))
            elif g.kind == 8:
                print(self.get(g.c))
                res = If(self.get(g.c), self.get(g.b), self.get(g.a))
            elif g.kind == 9:
                res = Xor(g.dff, g.n)
            g.value = res
            g.tstamp = self.cycles
        return g.value

    def step(self):
        for i in self.dffs:
            self.get(i)
        for i in self.dffs:
            self.gs[i].dff = self.get(self.gs[i].a)
        self.cycles += 1

e = E()
s = Solver()
bits = [Bool("x%d" % i) for i in range(80)]

for i in range(40):
    e.gs[e.key[0]].value = bits[i * 2]
    e.gs[e.key[1]].value = bits[i * 2 + 1]
    e.step()
    e.step()

s.add(e.get(e.good[0]) == True)
print(s.check())
m = s.model()

result = bytearray()
for i in range(10):
    n = 0
    for j in range(8):
        n += bool(m[bits[i * 8 + j]]) << j
    result.append(n)

print(result.hex())
