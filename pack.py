import re
from struct import pack, unpack
from collections import OrderedDict

from graphenebase import PublicKey

user_data_type_table = {
    2: "uint64",
    5: "string",
}

struct_definition_table = {
    "address": OrderedDict([
        ("remote_endpoint", "ipendp"),
        ("last_seen_time", "uint32"),
        ("latency", "int64"),
        ("node_id", "pubkey"),
        ("direction", "uint8"),
        ("firewalled", "uint8"),
    ]),
}

def unpack_field(msg: bytes, type_: any):
    if type(type_) is list:
        return unpack_vector(msg, type_)
    else:
        unpacker = type_unpack_table.get(type_, None)
        if unpacker is not None:
            return unpacker(msg)
        else:
            if type_ in struct_definition_table.keys():
                return unpack_struct(msg, type_)
            else:
                print("Unknown value type", type_)
                return None, msg

def unpack_varint(msg: bytes):
    value = 0
    i = 0
    while True:
        value += (msg[i] & 0x7f) << (i * 7)
        if msg[i] & 0x80 != 0x80:
            break
        i += 1
    return value, msg[i + 1:]

def unpack_struct(msg: bytes, type_):
    definition = struct_definition_table[type_]
    result = {}
    for name, type_ in definition.items():
        result[name], msg = unpack_field(msg, type_)
    return result, msg

def unpack_string(msg: bytes):
    length, msg = unpack_varint(msg)
    return (msg[:length]).decode("utf8"), msg[length:]

def unpack_uint8(msg: bytes):
    return msg[0], msg[1:]

def unpack_uint16(msg: bytes):
    return unpack("<H", msg[:2])[0], msg[2:]

def unpack_uint32(msg: bytes):
    return unpack("<I", msg[:4])[0], msg[4:]

def unpack_uint64(msg: bytes):
    return unpack("<Q", msg[:8])[0], msg[8:]

def unpack_int64(msg: bytes):
    return unpack("<q", msg[:8])[0], msg[8:]

def unpack_ipaddr(msg: bytes):
    return "%s.%s.%s.%s" % (msg[3], msg[2], msg[1], msg[0]), msg[4:]

def unpack_ipendp(msg: bytes):
    return "%s.%s.%s.%s:%s" % (msg[3], msg[2], msg[1], msg[0], unpack("<H", msg[4:6])[0]), msg[6:]

def unpack_pubkey(msg: bytes):
    return msg[:33].hex(), msg[33:]

def unpack_signature(msg: bytes):
    return msg[:65].hex(), msg[65:]

def unpack_sha256(msg: bytes):
    return msg[:32].hex(), msg[32:]

def unpack_object(msg: bytes):
    obj = {}
    # assuming count will not exceed 128
    count = msg[0]
    msg = msg[1:]
    for _ in range(count):
        key, msg = unpack_string(msg)
        type_ = user_data_type_table.get(msg[0], None)
        if type_ is None:
            print("Unknown user data type", msg[0])
            print(msg)
        value, msg = unpack_field(msg[1:], type_)
        obj[key] = value
    return obj, msg

def unpack_vector(msg: bytes, type_):
    obj = []
    # assuming count will not exceed 128
    count = msg[0]
    msg = msg[1:]
    for _ in range(count):
        value, msg = unpack_field(msg, type_[0])
        obj.append(value)
    return obj, msg

type_unpack_table = {
    "string": unpack_string,
    "uint8": unpack_uint8,
    "uint16": unpack_uint16,
    "uint32": unpack_uint32,
    "uint64": unpack_uint64,
    "int64": unpack_int64,
    "ipaddr": unpack_ipaddr,
    "ipendp": unpack_ipendp,
    "pubkey": unpack_pubkey,
    "sig": unpack_signature,
    "sha256": unpack_sha256,
    "object": unpack_object,
    "vector": unpack_vector,
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
