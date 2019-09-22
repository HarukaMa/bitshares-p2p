import logging
import re
from struct import pack, unpack
from collections import OrderedDict

from graphenebase import PublicKey

from .utils import Buffer

user_data_type_table = {
    2: "uint64",
    5: "string",
}

class Map:
    def __init__(self, key, value):
        self.key = key
        self.value = value

class Optional:
    def __init__(self, type_):
        self.type = type_

class Extension:
    def __init__(self, type_):
        self.type = type_

class StaticVariant:
    def __init__(self, types):
        self.types = types

struct_definition_table = {
    "address": OrderedDict([
        ("remote_endpoint", "ipendp"),
        ("last_seen_time", "uint32"),
        ("latency", "int64"),
        ("node_id", "pubkey"),
        ("direction", "uint8"),
        ("firewalled", "uint8")
    ]),
    "signed_block": OrderedDict([
        ("previous", "ripemd160"),
        ("timestamp", "uint32"),
        ("witness", "witness_id"),
        ("transaction_merkle_root", "ripemd160"),
        ("extensions", ["object"]),
        ("witness_signature", "sig"),
        ("transactions", ["transaction"])
    ]),
    "precomputable_transaction": OrderedDict([
        ("ref_block_num", "uint16"),
        ("ref_block_prefix", "uint32"),
        ("expiration", "uint32"),
        ("operations", ["operation"]),
        ("extensions", ["object"]),
        ("signatures", ["sig"]),
    ]),
    "transaction": OrderedDict([
        ("ref_block_num", "uint16"),
        ("ref_block_prefix", "uint32"),
        ("expiration", "uint32"),
        ("operations", ["operation"]),
        ("extensions", ["object"]),
        ("signatures", ["sig"]),
        ("operation_results", ["op_result"])
    ]),
    "asset": OrderedDict([
        ("amount", "int64"),
        ("asset_id", "asset_id")
    ]),
    "memo": OrderedDict([
        ("from", "pubkey"),
        ("to", "pubkey"),
        ("nonce", "uint64"),
        ("message", "varbyte")
    ]),
    "price": OrderedDict([
        ("base", "asset"),
        ("quote", "asset")
    ]),
    "price_feed": OrderedDict([
        ("settlement_price", "price"),
        ("maintenance_collateral_ratio", "uint16"),
        ("maximum_short_squeeze_ratio", "uint16"),
        ("core_exchange_rate", "price"),
    ]),
    "authority": OrderedDict([
        ("weight_threshold", "uint32"),
        ("account_auths", Map("account_id", "uint16")),
        ("key_auths", Map("pubkey", "uint16")),
        ("address_auths", Map("ripemd160", "uint16")),
    ]),
    "account_options": OrderedDict([
        ("memo_key", "pubkey"),
        ("voting_account", "account_id"),
        ("num_witness", "uint16"),
        ("num_committee", "uint16"),
        ("votes", ["vote_id"]),
        ("extensions", ["object"]),
    ]),
    "call_order_options": {
        "target_collateral_ratio": "uint16"
    },
    "linear_vesting": OrderedDict([
        ("begin_timestamp", "uint32"),
        ("vesting_cliff_seconds", "uint32"),
        ("vesting_duration_seconds", "uint32"),
    ]),
    "cdd_vesting": OrderedDict([
        ("start_claim", "uint32"),
        ("vesting_seconds", "uint32"),
    ]),
    "instant_vesting": {},
    "asset_options": OrderedDict([
        ("max_supply", "int64"),
        ("market_fee_percent", "uint16"),
        ("max_market_fee", "int64"),
        ("issuer_permissions", "uint16"),
        ("flags", "uint16"),
        ("core_exchange_rate", "price"),
        ("whitelist_authorities", ["account_id"]),
        ("blacklist_authorities", ["account_id"]),
        ("whitelist_markets", ["asset_id"]),
        ("blacklist_markets", ["asset_id"]),
        ("description", "string"),
        ("extensions", Extension("additional_asset_options")),
    ]),
    "additional_asset_options": OrderedDict([
        ("reward_percent", "uint16"),
        ("whitelist_market_fee_sharing", ["account_id"]),
    ]),
    "bitasset_options": OrderedDict([
        ("feed_lifetime_sec", "uint16"),
        ("minimum_feeds", "uint8"),
        ("force_settlement_delay_sec", "uint32"),
        ("force_settlement_offset_percent", "uint16"),
        ("maximum_force_settlement_volume", "uint16"),
        ("short_backing_asset", "asset_id"),
        ("extensions", ["object"]),
    ]),
}

operation_definition_table = {
    0: OrderedDict([
        ("fee", "asset"),
        ("from", "account_id"),
        ("to", "account_id"),
        ("amount", "asset"),
        ("memo", Optional("memo")),
        ("extensions", ["object"]),
    ]),
    1: OrderedDict([
        ("fee", "asset"),
        ("seller", "account_id"),
        ("amount_to_sell", "asset"),
        ("min_to_receive", "asset"),
        ("expiration", "uint32"),
        ("fill_or_kill", "bool"),
        ("extensions", ["object"]),
    ]),
    2: OrderedDict([
        ("fee", "asset"),
        ("order", "limit_order_id"),
        ("fee_paying_account", "account_id"),
        ("extensions", ["object"]),
    ]),
    3: OrderedDict([
        ("fee", "asset"),
        ("funding_account", "account_id"),
        ("delta_collateral", "asset"),
        ("delta_debt", "asset"),
        ("extensions", Extension("call_order_options")),
    ]),
    5: OrderedDict([
        ("fee", "asset"),
        ("registrar", "account_id"),
        ("referrer", "account_id"),
        ("referrer_percent", "uint16"),
        ("name", "string"),
        ("owner", "authority"),
        ("active", "authority"),
        ("options", "account_options"),
        ("extensions", ["object"]),
    ]),
    6: OrderedDict([
        ("fee", "asset"),
        ("account", "limit_order_id"),
        ("owner", Optional("authority")),
        ("active", Optional("authority")),
        ("new_options", Optional("account_options")),
        ("extensions", ["object"]),
    ]),
    10: OrderedDict([
        ("fee", "asset"),
        ("issuer", "account_id"),
        ("symbol", "string"),
        ("precision", "uint8"),
        ("common_options", "asset_options"),
        ("bitasset_opts", Optional("bitasset_options")),
        ("is_prediction_market", "bool"),
        ("extensions", ["object"]),
    ]),
    14: OrderedDict([
        ("fee", "asset"),
        ("issuer", "account_id"),
        ("asset_to_issue", "asset"),
        ("issue_to_account", "account_id"),
        ("memo", Optional("memo")),
        ("extensions", ["object"]),
    ]),
    15: OrderedDict([
        ("fee", "asset"),
        ("payer", "account_id"),
        ("amount_to_reserve", "asset"),
        ("extensions", ["object"]),
    ]),
    16: OrderedDict([
        ("fee", "asset"),
        ("from_account", "account_id"),
        ("asset_id", "asset_id"),
        ("amount", "int64"),
        ("extensions", ["object"]),
    ]),
    17: OrderedDict([
        ("fee", "asset"),
        ("account", "account_id"),
        ("amount", "asset"),
        ("extensions", ["object"]),
    ]),
    19: OrderedDict([
        ("fee", "asset"),
        ("publisher", "account_id"),
        ("asset_id", "asset_id"),
        ("feed", "price_feed"),
        ("extensions", ["object"]),
    ]),
    20: OrderedDict([
        ("fee", "asset"),
        ("witness_account", "account_id"),
        ("url", "string"),
        ("block_signing_key", "pubkey"),
    ]),
    22: OrderedDict([
        ("fee", "asset"),
        ("fee_paying_account", "account_id"),
        ("expiration_time", "uint32"),
        ("proposed_ops", ["operation"]),
        ("review_period_seconds", Optional("uint32")),
        ("extensions", ["object"]),
    ]),
    23: OrderedDict([
        ("fee", "asset"),
        ("fee_paying_account", "account_id"),
        ("proposal", "proposal_id"),
        ("active_approvals_to_add", ["account_id"]),
        ("active_approvals_to_remove", ["account_id"]),
        ("owner_approvals_to_add", ["account_id"]),
        ("owner_approvals_to_remove", ["account_id"]),
        ("key_approvals_to_add", ["pubkey"]),
        ("key_approvals_to_remove", ["pubkey"]),
        ("extensions", ["object"]),
    ]),
    32: OrderedDict([
        ("fee", "asset"),
        ("creator", "account_id"),
        ("owner", "account_id"),
        ("amount", "asset"),
        ("policy", StaticVariant([
            "linear_vesting",
            "cdd_vesting",
            "instant_vesting"
        ])),
    ]),
    33: OrderedDict([
        ("fee", "asset"),
        ("vesting_balance", "balance_id"),
        ("owner", "account_id"),
        ("amount", "asset"),
    ]),
    37: OrderedDict([
        ("fee", "asset"),
        ("deposit_to_account", "account_id"),
        ("balance_to_claim", "balance_id"),
        ("balance_owner_key", "pubkey"),
        ("total_claimed", "asset"),
    ]),
    43: OrderedDict([
        ("fee", "asset"),
        ("issuer", "account_id"),
        ("amount_to_claim", "asset"),
        ("extensions", ["object"]),
    ]),
    47: OrderedDict([
        ("fee", "asset"),
        ("issuer", "account_id"),
        ("asset_id", "asset_id"),
        ("amount_to_claim", "asset"),
        ("extensions", ["object"]),
    ]),
}

type_id_definition_table = {
    "account_id": (1, 2),
    "asset_id": (1, 3),
    "witness_id": (1, 6),
    "limit_order_id": (1, 7),
    "proposal_id": (1, 11),
    "balance_id": (1, 13),
}

def unpack_field(msg: Buffer, type_: any):
    if type(type_) is list:
        return unpack_vector(msg, type_[0])
    if type(type_) is Optional:
        return unpack_optional(msg, type_.type)
    if type(type_) is Map:
        return unpack_map(msg, type_)
    if type(type_) is Extension:
        return unpack_extension(msg, type_)
    if type(type_) is StaticVariant:
        return unpack_static_variant(msg, type_)
    unpacker = type_unpack_table.get(type_, None)
    if unpacker is not None:
        return unpacker(msg)
    if type_ in struct_definition_table.keys():
        return unpack_struct(msg, type_)
    if type_ in type_id_definition_table.keys():
        return unpack_oid(msg, type_)
    logging.error("Unknown value type %s" % type_)
    assert False

def unpack_struct(msg: Buffer, type_):
    definition = struct_definition_table[type_]
    res = {}
    for name, type_ in definition.items():
        res[name] = unpack_field(msg, type_)
    return res

def unpack_optional(msg: Buffer, type_):
    null = ord(msg.read(1))
    if null == 0:
        return None
    else:
        return unpack_field(msg, type_)

def unpack_map(msg: Buffer, type_: Map):
    res = {}
    length = unpack_varint(msg)
    for _ in range(length):
        key = unpack_field(msg, type_.key)
        res[key] = unpack_field(msg, type_.value)
    return res

def unpack_extension(msg: Buffer, type_: Extension):
    res = {}
    length = unpack_varint(msg)
    definition = struct_definition_table[type_.type]
    items = list(definition.items())
    for i in range(length):
        index = unpack_varint(msg)
        assert index == i
        res[items[i][0]] = unpack_field(msg, items[i][1])
    return res

def unpack_static_variant(msg: Buffer, type_: StaticVariant):
    index = unpack_varint(msg)
    return unpack_field(msg, type_.types[index])

def unpack_varint(msg: Buffer):
    value = 0
    i = 0
    while True:
        byte = ord(msg.read(1))
        value += (byte & 0x7f) << (i * 7)
        if byte & 0x80 != 0x80:
            break
        i += 1
    return value

def unpack_string(msg: Buffer):
    length = unpack_varint(msg)
    return (msg.read(length)).decode("utf8")

def unpack_varbyte(msg: Buffer):
    length = unpack_varint(msg)
    return msg.read(length).hex()

def unpack_bool(msg: Buffer):
    return True if ord(msg.read(1)) == 1 else False

def unpack_uint8(msg: Buffer):
    return ord(msg.read(1))

def unpack_uint16(msg: Buffer):
    return unpack("<H", msg.read(2))[0]

def unpack_uint32(msg: Buffer):
    return unpack("<I", msg.read(4))[0]

def unpack_uint64(msg: Buffer):
    return unpack("<Q", msg.read(8))[0]

def unpack_int64(msg: Buffer):
    return unpack("<q", msg.read(8))[0]

def unpack_ipaddr(msg: Buffer):
    data = msg.read(4)
    return "%s.%s.%s.%s" % (data[3], data[2], data[1], data[0])

def unpack_ipendp(msg: Buffer):
    data = msg.read(6)
    return "%s.%s.%s.%s:%s" % (data[3], data[2], data[1], data[0], unpack("<H", data[4:6])[0])

def unpack_pubkey(msg: Buffer):
    return msg.read(33).hex()

def unpack_signature(msg: Buffer):
    return msg.read(65).hex()

def unpack_sha256(msg: Buffer):
    return msg.read(32).hex()

def unpack_ripemd160(msg: Buffer):
    return msg.read(20).hex()

def unpack_object(msg: Buffer):
    obj = {}
    count = unpack_varint(msg)
    for _ in range(count):
        key = unpack_string(msg)
        byte = ord(msg.read(1))
        type_ = user_data_type_table.get(byte, None)
        if type_ is None:
            logging.error("Unknown user data type", byte)
            logging.error(msg)
        value = unpack_field(msg, type_)
        obj[key] = value
    return obj

def unpack_vector(msg: Buffer, type_):
    obj = []
    count = unpack_varint(msg)
    for _ in range(count):
        value = unpack_field(msg, type_)
        obj.append(value)
    return obj

def unpack_oid(msg: Buffer, type_):
    if type_ is None:
        data = unpack("<Q", msg.read(8))[0]
        space = (data & (0xff << 56)) >> 56
        type_ = (data & (0xff << 48)) >> 48
        id_ = data & 0xffffffffffff
        return "%d.%d.%d" % (space, type_, id_)
    else:
        fields = type_id_definition_table[type_]
        id_ = unpack_varint(msg)
        return "%d.%d.%d" % (fields[0], fields[1], id_)

def unpack_vote_id(msg: Buffer):
    value = unpack("<I", msg.read(4))[0]
    type_ = value & 0xff
    instance = (value & 0xffffff00) >> 8
    return "%d:%d" % (type_, instance)

def unpack_operation(msg: Buffer):
    op_type = ord(msg.read(1))
    op = {}
    res = [op_type, op]
    definition = operation_definition_table.get(op_type, None)
    if definition is not None:
        for name, type_ in definition.items():
            op[name] = unpack_field(msg, type_)
        return res
    logging.error("Unknown operation type %d" % op_type)
    assert False

def unpack_op_result(msg: Buffer):
    res_type = ord(msg.read(1))
    res = [res_type]
    if res_type == 0:
        res.append(None)
    elif res_type == 1:
        res.append(unpack_oid(msg, None))
    elif res_type == 2:
        res.append(unpack_struct(msg, "asset"))
    return res


type_unpack_table = {
    "string": unpack_string,
    "varbyte": unpack_varbyte,
    "bool": unpack_bool,
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
    "vote_id": unpack_vote_id,
    "operation": unpack_operation,
    "op_result": unpack_op_result,
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
        v = msg & 0x7f
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
