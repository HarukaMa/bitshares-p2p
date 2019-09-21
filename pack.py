import re
from struct import pack, unpack

from graphenebase import PublicKey

user_data_type_table = {
    2: "uint64",
    5: "string",
}

def unpack_field(type_: str, msg: bytes):
    unpacker = type_unpack_table.get(type_, None)
    if unpacker is None:
        print("Unknown value type", type_)
        return None, msg
    value, length = unpacker(msg)
    return value, msg[length:]

def unpack_varint(msg: bytes):
    value = 0
    i = 0
    while True:
        value += (msg[i] & 0x7f) << (i * 7)
        if msg[i] & 0x80 != 0x80:
            break
        i += 1
    return value, i + 1

def unpack_string(msg: bytes):
    length, consumed = unpack_varint(msg)
    return (msg[consumed:consumed + length]).decode("utf8"), consumed + length

def unpack_uint8(msg: bytes):
    return msg[0], 1

def unpack_uint16(msg: bytes):
    return unpack("<H", msg[:2])[0], 2

def unpack_uint32(msg: bytes):
    return unpack("<I", msg[:4])[0], 4

def unpack_uint64(msg: bytes):
    return unpack("<Q", msg[:8])[0], 8

def unpack_ipaddr(msg: bytes):
    return "%s.%s.%s.%s" % (msg[3], msg[2], msg[1], msg[0]), 4

def unpack_ipendp(msg: bytes):
    return "%s.%s.%s.%s:%s" % (msg[3], msg[2], msg[1], msg[0], unpack("<H", msg[4:6])[0]), 6

def unpack_pubkey(msg: bytes):
    return msg[:33].hex(), 33

def unpack_signature(msg: bytes):
    return msg[:65].hex(), 65

def unpack_sha256(msg: bytes):
    return msg[:32].hex(), 32

def unpack_object(msg: bytes):
    obj = {}
    count = msg[0]
    msg = msg[1:]
    for _ in range(count):
        key, length = unpack_string(msg)
        msg = msg[length:]
        type_ = user_data_type_table.get(msg[0], None)
        if type_ is None:
            print("Unknown user data type", msg[0])
            print(msg)
        value, msg = unpack_field(type_, msg[1:])
        obj[key] = value
    return obj, len(msg)

type_unpack_table = {
    "string": unpack_string,
    "uint8": unpack_uint8,
    "uint16": unpack_uint16,
    "uint32": unpack_uint32,
    "uint64": unpack_uint64,
    "ipaddr": unpack_ipaddr,
    "ipendp": unpack_ipendp,
    "pubkey": unpack_pubkey,
    "sig": unpack_signature,
    "sha256": unpack_sha256,
    "object": unpack_object,
}

def pack_field(type_: str, msg: any):
    packer = type_pack_table.get(type_, None)
    if packer is None:
        print("Unknown value type", type_)
        return None
    return packer(msg)

def pack_varint(msg: int):
    res = bytearray()
    while msg > 0:
        v = msg % 0x7f
        if msg - 128 > 0:
            v |= 0x80
        res.append(v)
        msg >>= 7
        if msg == 0:
            break
    return res

def pack_string(msg: str):
    res = pack_varint(len(msg))
    return res + bytearray(msg.encode("utf8"))

def pack_uint16(msg: int):
    return pack("<H", msg)

def pack_uint32(msg: int):
    return pack("<I", msg)

def pack_uint64(msg: int):
    return pack("<Q", msg)

def pack_ipaddr(msg: str):
    msg = list(map(int, msg.split(".")))
    return bytearray([msg[3], msg[2], msg[1], msg[0]])

def pack_ipendp(msg: str):
    msg = list(map(int, re.split(r":\.", msg)))
    return bytearray([msg[3], msg[2], msg[1], msg[0]]) + pack("<H", msg[4])

def pack_pubkey(msg: PublicKey):
    return bytes.fromhex(repr(msg))

def pack_signature(msg: bytes):
    return msg

def pack_sha256(msg: bytes):
    return msg

def pack_object(msg: dict):
    res = bytearray()
    res += pack_varint(len(msg))
    for k, v in msg.items():
        res += pack_string(k)
        if type(v) is int:
            res.append(2)
            res += pack_uint64(v)
        elif type(v) is str:
            res.append(5)
            res += pack_string(v)
        else:
            print("Unknown user data type", type(v))
    return res

type_pack_table = {
    "string": pack_string,
    "uint16": pack_uint16,
    "uint32": pack_uint32,
    "uint64": pack_uint64,
    "ipaddr": pack_ipaddr,
    "ipendp": pack_ipendp,
    "pubkey": pack_pubkey,
    "sig": pack_signature,
    "sha256": pack_sha256,
    "object": pack_object,
}
