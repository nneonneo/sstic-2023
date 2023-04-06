import h5py
from matplotlib import pyplot as plt

f = h5py.File('data_34718ec031bbb6e094075a0c7da32bc5056a57ff082c206e6b70fcc864df09e9.h5', 'r')

ax = plt.gca()
ax.set_ylim([0.1, 0.25])

for i in range(100):
    plt.plot(f["leakages"][i], '.-')
    print(bytearray(f["mask"][i]).hex())

plt.show(block=True)
