import logging
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
    "signed_block": OrderedDict([
        ("previous", "ripemd160"),
        ("timestamp", "uint32"),
        ("witness", "oid"),
        ("transaction_merkle_root", "ripemd160"),
        ("extensions", ["object"]),
        ("witness_signature", "sig"),
        ("transactions", ["transaction"]),
    ]),
    "transaction": OrderedDict([

    ])
}

def unpack_field(msg: bytes, type_: any):
    if type(type_) is list:
        return unpack_vector(msg, type_[0])
    unpacker = type_unpack_table.get(type_, None)
    if unpacker is not None:
        return unpacker(msg)
    if type_ in struct_definition_table.keys():
        return unpack_struct(msg, type_)
    logging.error("Unknown value type", type_)
    return None, msg

def unpack_struct(msg: bytes, type_):
    definition = struct_definition_table[type_]
    res = {}
    for name, type_ in definition.items():
        res[name], msg = unpack_field(msg, type_)
    return res, msg

def unpack_varint(msg: bytes):
    value = 0
    i = 0
    while True:
        value += (msg[i] & 0x7f) << (i * 7)
        if msg[i] & 0x80 != 0x80:
            break
        i += 1
    return value, msg[i + 1:]

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

def unpack_ripemd160(msg: bytes):
    return msg[:20].hex(), msg[20:]

def unpack_object(msg: bytes):
    obj = {}
    count, msg = unpack_varint(msg)
    for _ in range(count):
        key, msg = unpack_string(msg)
        type_ = user_data_type_table.get(msg[0], None)
        if type_ is None:
            logging.error("Unknown user data type", msg[0])
            logging.error(msg)
        value, msg = unpack_field(msg[1:], type_)
        obj[key] = value
    return obj, msg

def unpack_vector(msg: bytes, type_):
    obj = []
    count, msg = unpack_varint(msg)
    for _ in range(count):
        value, msg = unpack_field(msg, type_)
        obj.append(value)
    return obj, msg

def unpack_oid(msg: bytes):
    data = unpack("<Q", msg[:8])[0]
    space = (data & (0xff << 56)) >> 56
    type_ = (data & (0xff << 48)) >> 48
    id_ = data & 0xffffffffffff
    return "%d.%d.%d" % (space, type_, id_), msg[8:]

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
    "ripemd160": unpack_ripemd160,
    "object": unpack_object,
    "vector": unpack_vector,
    "oid": unpack_oid,
}

def pack_field(msg: any, type_: any):
    if type(type_) is list:
        return pack_vector(msg, type_[0])
    packer = type_pack_table.get(type_, None)
    if packer is not None:
        return packer(msg)
    if type_ in struct_definition_table.keys():
        return pack_struct(msg, type_)
    logging.error("Unknown value type", type_)
    return None

def pack_struct(msg: dict, type_):
    definition = struct_definition_table[type_]
    res = bytearray()
    for name, type_ in definition.items():
        res.extend(pack_field(msg.get(name, None), type_))
    return res

def pack_varint(msg: int):
    res = bytearray()
    while True:
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

def pack_uint8(msg: int):
    return bytes([msg])

def pack_uint16(msg: int):
    return pack("<H", msg)

def pack_uint32(msg: int):
    return pack("<I", msg)

def pack_uint64(msg: int):
    return pack("<Q", msg)

def pack_int64(msg: int):
    return pack("<q", msg)

def pack_ipaddr(msg: str):
    msg = list(map(int, msg.split(".")))
    return bytearray([msg[3], msg[2], msg[1], msg[0]])

def pack_ipendp(msg: str):
    msg = list(map(int, re.split(r"[:\.]", msg)))
    return bytearray([msg[3], msg[2], msg[1], msg[0]]) + pack("<H", msg[4])

def pack_pubkey(msg: PublicKey):
    return bytes.fromhex(repr(msg))

def pack_signature(msg: bytes):
    return msg

def pack_sha256(msg: bytes):
    return msg

def pack_ripemd160(msg: str):
    # just use as id here
    return bytes.fromhex(msg)

def pack_object(msg: dict):
    res = bytearray()
    res.extend(pack_varint(len(msg)))
    for k, v in msg.items():
        res.extend(pack_string(k))
        if type(v) is int:
            res.append(2)
            res.extend(pack_uint64(v))
        elif type(v) is str:
            res.append(5)
            res.extend(pack_string(v))
        else:
            logging.error("Unknown user data type", type(v))
    return res

def pack_vector(msg: list, type_):
    res = bytearray()
    res.extend(pack_varint(len(msg)))
    for i in msg:
        res.extend(pack_field(i, type_))
    return res

type_pack_table = {
    "string": pack_string,
    "uint8": pack_uint8,
    "uint16": pack_uint16,
    "uint32": pack_uint32,
    "uint64": pack_uint64,
    "int64": pack_int64,
    "ipaddr": pack_ipaddr,
    "ipendp": pack_ipendp,
    "pubkey": pack_pubkey,
    "sig": pack_signature,
    "sha256": pack_sha256,
    "ripemd160": pack_ripemd160,
    "object": pack_object,
    "vector": pack_vector,
}
