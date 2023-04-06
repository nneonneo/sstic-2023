import h5py
from matplotlib import pyplot as plt

f = h5py.File('data_34718ec031bbb6e094075a0c7da32bc5056a57ff082c206e6b70fcc864df09e9.h5', 'r')

hamming = [sum(int(c) for c in f"{i:b}") for i in range(256)]

leakages = f["leakages"]
masks = f["mask"]
key = [None] * 32
for i in range(25000):
    mask = masks[i]
    # gotta love synthetic data
    bits = leakages[i][421:485:2]
    if (bits < 0.11).all():
        continue
    bits = [int(round(c)) for c in ((bits - 0.13) / 0.005)]
    for j, b in enumerate(bits):
        if key[j] is not None:
            assert hamming[key[j] ^ mask[j]] == b
        elif b == 0:
            key[j] = masks[i][j]
        elif b == 8:
            key[j] = 255 - masks[i][j]

print(bytearray(key).hex())
