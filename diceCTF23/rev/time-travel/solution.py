
import struct
import numpy as np
from ctypes import *


with open("input.bin", 'rb') as f:
    data = f.read()
assert(len(data) == 0x28a04)

flag = ''
N = struct.unpack("<i", data[:4])[0]
print(f"N: {hex(N)}")
for i in range(0x40):
    matrix = np.zeros((N, N))
    matrix_offset = 2600*i
    for k in range(N):
        row_offset = matrix_offset + 4 + k*0x12*8
        for j in range(N):
            offset = row_offset + j*8
            matrix[k][j] = struct.unpack("<q", data[offset:(offset+8)])[0]
    # print(matrix)
    stored_char = c_uint8(data[matrix_offset+2596]).value
    det = np.linalg.det(matrix)
    final_det = c_long(round(det)).value

    print(f"stored_char: {hex(stored_char)}")
    print(f"det        : {det}")
    print(f"final_det  : {final_det}")

    # putchar(i + (char)((char)*(undefined8 *)&piVar1[i].stored_char - (char)lVar1));
    res = i + (stored_char - (final_det & 0xff))
    c = c_uint8(res).value
    print(f"res: {res}, c: {c}")
    print(f"chr: {chr(c)}")
    print()
    flag += chr(c)
print(flag) # dice{d3t4rm1n1NanT5_c4n_b3_F4sT_1a7sN2j1867327mA6jmapc817jgd6m0}
    


