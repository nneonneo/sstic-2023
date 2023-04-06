#!/bin/env python3
import sys

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

GNAMES = ["zero", "one", "val", "buf", "and", "or", "xor", "not", "mux", "ff"]
GSHAPES = ["proteasesite", "proteinstab", "utr", "invtriangle", "invtrapezium", "invhouse", "pentagon", "invtriangle", "diamond", "rectangle"]
e = E()
print("digraph G {")
def line(a, b, inv=False, control=False):
    ga = e.gs[a]
    gb = e.gs[b]
    attrs = ["dir=both"]
    if ga.kind in (0, 1):
        print(f"\"{a}_{b}\" [shape={GSHAPES[ga.kind]},label=\"{GNAMES[ga.kind]}_{a}_{b}\"];")
        a = f"\"{a}_{b}\""
    if ga.kind in (6, 9) and ga.n:
        attrs.append("arrowtail=odot")
    else:
        attrs.append("arrowtail=none")
    if inv:
        attrs.append("arrowhead=odotnormal")
    else:
        attrs.append("arrowhead=normal")
    if control:
        attrs.append("style=dashed")
    print(f"{a} -> {b} [{','.join(attrs)}];")

for i, g in enumerate(e.gs):
    name = GNAMES[g.kind]
    if i in e.key:
        shape = "circle"
    elif i in e.good:
        shape = "doublecircle"
    elif i in e.data:
        shape = "star"
    else:
        shape = GSHAPES[g.kind]
    if name == "ff":
        extra = f"_{g.dff}"
    else:
        extra = ""
    print(f"{i} [shape={shape},label=\"{name}_{i}{extra}\"];")
    if g.kind in [4, 5]:
        line(g.a, i, inv=g.na)
        line(g.b, i, inv=g.nb)
    elif g.kind in [3, 7, 9]:
        line(g.a, i)
    elif g.kind == 6:
        line(g.a, i)
        line(g.b, i)
    elif g.kind == 8:
        line(g.a, i)
        line(g.b, i)
        line(g.c, i, control=True)

print("}")
