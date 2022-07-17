
import struct
from pwnlib.util.fiddling import hexdump

with open('dump.zip', 'rb') as f:
    dumpzip=f.read()


def parse_zip(eof_cd_offset):
    '''eof_cd_offset - Offset in dumpzip where the end of central directory record (EoCD) starts'''
    # End of central directory record offset
    # print(hexdump(dumpzip[eof_cd_offset:eof_cd_offset+0x30]))
    eof_cd_record_h=dumpzip[eof_cd_offset:eof_cd_offset+22]   # without the variable sized comment

    print("Dumping EOF CD Record")
    print(hexdump(eof_cd_record_h))

    entries_in_central_directory = struct.unpack("<H", eof_cd_record_h[10:12])[0]
    size_of_central_directory    = struct.unpack("<I", eof_cd_record_h[12:16])[0]
    offset_of_start_of_central   = struct.unpack("<I", eof_cd_record_h[16:20])[0]

    print(f" [*] Central directory [{offset_of_start_of_central}, {offset_of_start_of_central+size_of_central_directory})")
    print(f" [*] Num of entries: {entries_in_central_directory}")


    print("Dumping CD record")
    cd_record_h = dumpzip[offset_of_start_of_central:offset_of_start_of_central+46]
    assert(struct.unpack("<I", cd_record_h[0:4])[0] == 0x02014b50)
    print(hexdump(cd_record_h))

    relative_offset_of_local_header = struct.unpack("<I", cd_record_h[42:46])[0]

    print("Dumping Local File Header")
    lf_header_h = dumpzip[relative_offset_of_local_header:relative_offset_of_local_header+30]
    print(hexdump(lf_header_h))
    assert(struct.unpack("<I", lf_header_h[0:4])[0] == 0x04034b50)
    compressed_size  = struct.unpack("<I", lf_header_h[18:22])[0]
    file_name_length = struct.unpack("<H", lf_header_h[26:28])[0]

    # flag_char = dumpzip[relative_offset_of_local_header+30+6]
    data = dumpzip[relative_offset_of_local_header+30+file_name_length:relative_offset_of_local_header+30+file_name_length+compressed_size]
    print(data)
    return data


assert(len(dumpzip) < 65557) # otherwise we would have to scan only the last part
flag = b''
for i in range(len(dumpzip)-4):
    magic_num = struct.unpack("<I", dumpzip[i:i+4])[0]
    if(magic_num == 0x06054b50): # End of central directory record
        print("-------------------- PARSING --------------------")
        print(f"Found end of End of central directory record at offset {i}")
        ch = parse_zip(i)
        flag += ch
        print("-------------------- ------ --------------------\n")
print(flag.decode('ascii')) # CTF{p0s7m0d3rn_z1p}
