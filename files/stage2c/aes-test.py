from Crypto.Cipher import AES
import os
from pwn import p32, u32, p64, u64, log
from dataclasses import dataclass
from typing import Optional
from zlib import crc32
import struct
from functools import cache
from tqdm import tqdm

@dataclass
class Message:
    mode: int = 0
    size_mode0: Optional[int] = None
    id: int = 0
    data: bytes = b""
    crc: Optional[int] = None
    size_mode1: Optional[int] = None

    def to_bytes(self):
        if self.crc is None:
            self.crc = crc32(self.data) & 0xffffffff
        if self.size_mode0 is None:
            self.size_mode0 = len(self.data)
        if self.size_mode1 is None:
            self.size_mode1 = len(self.data)
        return struct.pack("<III256sII",
            self.mode, self.size_mode0, self.id, self.data, self.crc, self.size_mode1)

    @classmethod
    def from_bytes(cls, data):
        res = cls(*struct.unpack("<III256sII", data))
        res.data = res.data.rstrip(b"\0")
        return res

def xor(a, b):
    return bytes([ca^cb for ca,cb in zip(a,b)])

# emulation
SECRET_AES_KEY = os.urandom(32)

MEMORY = bytearray(0x1000)
MEMORY[0xd30:0xd38] = p64(0xdeadbeeffeed1e94) # x30
MEMORY[0xd40:0xd48] = p64(0xf00fb00bd00d13b0) # sp
MEMORY[0xc28:0xcc8] = os.urandom(16*10) # nonces

def clear():
    MEMORY[0x48:0x48 + 0xac8 + 4] = b"\0" * (0xac8 + 4)

def add(m):
    n = u32(MEMORY[0xb10:0xb14])
    MEMORY[0x48 + n * 0x114:0x48 + (n+1)*0x114] = m.to_bytes()
    MEMORY[0xb10:0xb14] = p32(n + 1)

def encrypt(n):
    i = 0
    results = []
    while 1:
        n = u32(MEMORY[0xb10:0xb14])
        if i >= n: break
        base = 0x48 + i * 0x114
        m = Message.from_bytes(MEMORY[base: base + 0x114])
        iv = MEMORY[0xc28 + i * 0x10: 0xc28 + (i+1) * 0x10]
        sz = m.size_mode0
        print("...encrypt %d/%d [%d bytes]" % (i, n, sz))
        assert base + 0xc + sz <= 0x1000
        MEMORY[base + 0xc:base + 0xc + sz] = AES.new(SECRET_AES_KEY, mode=AES.MODE_CBC, iv=iv).encrypt(MEMORY[base + 0xc:base + 0xc + sz])
        MEMORY[base + 0x110:base + 0x114] = p32(sz)
        MEMORY[base] = 1
        i += 1
        results.append(Message.from_bytes(MEMORY[base:base+0x114]))
    clear()
    return results

def decrypt(n):
    i = 0
    results = []
    while 1:
        n = u32(MEMORY[0xb10:0xb14])
        if i >= n: break
        base = 0x48 + i * 0x114
        m = Message.from_bytes(MEMORY[base: base + 0x114])
        iv = MEMORY[0xc28 + i * 0x10: 0xc28 + (i+1) * 0x10]
        sz = m.size_mode1
        print("...decrypt %d/%d [%d bytes]" % (i, n, sz))
        assert base + 0xc + sz <= 0x1000
        MEMORY[base] = 0
        MEMORY[base + 0xc:base + 0xc + sz] = AES.new(SECRET_AES_KEY, mode=AES.MODE_CBC, iv=iv).decrypt(MEMORY[base + 0xc:base + 0xc + sz])
        MEMORY[base + 4:base + 8] = p32(sz)
        i += 1
        results.append(Message.from_bytes(MEMORY[base:base+0x114]))
    clear()
    return results

@cache
def decrypt_block(block):
    add(Message(mode=1, data=b"\0" * 16 + block))
    data = decrypt(1)
    return data[-1].data.ljust(32, b"\0")[16:32]

# attack
CRC = crc32(b"A" * 16)

def decrypt_msg9(size):
    """ Overflowing decryption from message 9. Uses (CRC, size, 10, 0) as the IV for overflowed blocks. """
    block_old = struct.pack("<IIII", CRC, size, 10, 0)
    block_new = struct.pack("<IIII", 0xaaaaaaaa, 0xbbbbbbbb, 0, 0)
    block_dec = decrypt_block(block_old)
    block_enc = xor(block_new, block_dec)

    for i in range(9):
        add(Message(mode=0, data=b"A" * 16))
    add(Message(mode=0, data=b"A" * 240 + block_enc, size_mode0=16, size_mode1=size, crc=CRC))
    decrypt(10)

def encrypt_msg9(size, size1):
    """ Overflowing encryption from message 9. Uses (CRC, size1, 10, 0) as the IV for overflowed blocks. """
    block_old = struct.pack("<IIII", CRC, 16, 10, 0)
    block_new = struct.pack("<IIII", CRC, size1, 10, 0)
    block_dec = decrypt_block(block_new)
    prev_block_enc = xor(block_old, block_dec)
    prev_block_dec = decrypt_block(prev_block_enc)

    for i in range(9):
        add(Message(mode=0, data=b"A" * 16))
    add(Message(mode=0, data=b"A" * 256))
    data = encrypt(10)

    prev_block_pt = xor(data[-1].data[224:240], prev_block_dec)

    for i in range(9):
        add(Message(mode=0, data=b"A" * 16))
    add(Message(mode=1, size_mode0=size, data=b"A" * 240 + prev_block_pt, size_mode1=16, crc=CRC))
    encrypt(10)

def munge_272(diff):
    block_old = struct.pack("<IIII", CRC, 16, 10, 0)
    block_dec = decrypt_block(block_old)
    block_new = struct.pack("<IIII", CRC, 288, diff ^ 10, 0)
    block_enc = xor(block_new, block_dec)
    b2_old = struct.pack("<IIII", 0, CRC, 16, 0)
    b2_dec = decrypt_block(b2_old)
    b2_enc = xor(b2_old, b2_dec)
    b3_old = struct.pack("<IIII", 0, 0, CRC, 16)
    b3_dec = decrypt_block(b3_old)
    b3_enc = xor(b3_old, b3_dec)
    b4_old = struct.pack("<IIII", 16, 0, 16, 0)
    b4_dec = decrypt_block(b4_old)
    b4_enc = xor(b4_dec, b4_old)
    b5_old = struct.pack("<IIII", CRC, 0x114 * 5 + 12, 0, 16)
    b5_dec = decrypt_block(b5_old)
    b5_enc = xor(b5_dec, b5_old)
    b9_want = struct.pack("<IIII", 0, 0, 0, 0)
    b9_dec1 = decrypt_block(block_enc)
    b9_dec2 = decrypt_block(block_new)
    b9_enc = xor(b9_want, xor(b9_dec1, b9_dec2))

    add(Message(mode=0, data=b"A" * 16))
    add(Message(mode=0, data=b"A" * 16, size_mode1=0x114 * 9 - 4, crc=CRC))
    add(Message(mode=0, data=b"A" * 16 + b"X" * 220 + b2_enc, size_mode0=16, size_mode1=16, crc=CRC))
    add(Message(mode=0, data=b"A" * 16 + b"X" * 216 + b3_enc, size_mode0=16, size_mode1=16, crc=CRC))
    add(Message(mode=0, data=b"A" * 16 + b"X" * 228 + b4_enc[:12], size_mode0=16, size_mode1=16, crc=CRC))
    add(Message(mode=0, data=b"A" * 240 + b5_enc, size_mode0=16, size_mode1=0x114 * 5 + 12, crc=CRC))
    add(Message(mode=0, data=b"A" * 16))
    add(Message(mode=0, data=b"A" * 16))
    add(Message(mode=0, data=b"A" * 16))
    add(Message(mode=0, data=b"A" * 16 + b"\0" * 208 + b9_enc + block_enc, size_mode0=16, size_mode1=16, crc=CRC))
    decrypt(10)

def forward_pass(distance, diff):
    SCHEDULE = list(range(distance, 272, -16))
    for L in tqdm(SCHEDULE):
        encrypt_msg9(L, L)

    munge_272(diff)

    for L in tqdm(SCHEDULE[::-1][1:]):
        decrypt_msg9(L)

def reverse_pass(distance_new, distance, diff):
    SCHEDULE = list(range(distance, 272, -16))
    for L in tqdm(SCHEDULE):
        encrypt_msg9(min(distance_new, L), L)

    munge_272(diff)

    for L in tqdm(SCHEDULE[::-1][1:]):
        decrypt_msg9(min(distance_new, L))

sp_diff = 0xa0
cur_x30 = 0x1e94
new_x30 = 0x1218

forward_pass(832, sp_diff)
reverse_pass(816, 832, sp_diff)
print(MEMORY.hex())
forward_pass(816, new_x30 ^ cur_x30)

print(MEMORY.hex())
