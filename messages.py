import datetime
import logging
from collections import OrderedDict
from hashlib import sha256
from pprint import pformat
from struct import unpack

from graphenebase import ecdsa, PublicKey

from .pack import unpack_field
from .utils import Buffer

message_name_table = {
    1000: "trx_message_type",
    1001: "block_message_type",
    5000: "core_message_type",
    5001: "item_ids_inventory_message_type",
    5002: "blockchain_item_ids_inventory_message_type",
    5003: "fetch_blockchain_item_ids_message_type",
    5004: "fetch_items_message_type",
    5005: "item_not_available_message_type",
    5006: "hello_message_type",
    5007: "connection_accepted_message_type",
    5008: "connection_rejected_message_type",
    5009: "address_request_message_type",
    5010: "address_message_type",
    5011: "closing_connection_message_type",
    5012: "current_time_request_message_type",
    5013: "current_time_reply_message_type",
    5014: "check_firewall_message_type",
    5015: "check_firewall_reply_message_type",
    5016: "get_current_connections_request_message_type",
    5017: "get_current_connections_reply_message_type",
    5099: "core_message_type",
}

message_definition_table = {
    1000: {
        "trx": "precomputable_transaction"
    },
    1001: OrderedDict([
        ("block", "signed_block"),
        ("block_id", "ripemd160")
    ]),
    5001: OrderedDict([
        ("item_type", "uint32"),
        ("item_hashes_available", ["ripemd160"])
    ]),
    5002: OrderedDict([
        ("total_remaining_item_count", "uint32"),
        ("item_type", "uint32"),
        ("item_hashes_available", ["ripemd160"])
    ]),
    5003: OrderedDict([
        ("item_type", "uint32"),
        ("blockchain_synopsis", ["ripemd160"])
    ]),
    5004: OrderedDict([
        ("item_type", "uint32"),
        ("items_to_fetch", ["ripemd160"])
    ]),
    5006: OrderedDict([
        ("user_agent", "string"),
        ("core_protocol_version", "uint32"),
        ("inbound_address", "ipaddr"),
        ("inbound_port", "uint16"),
        ("outbound_port", "uint16"),
        ("node_public_key", "pubkey"),
        ("signed_shared_secret", "sig"),
        ("chain_id", "sha256"),
        ("user_data", "object"),
    ]),
    5007: {},
    5008: OrderedDict([
        ("user_agent", "string"),
        ("core_protocol_version", "uint32"),
        ("remote_endpoint", "ipendp"),
        ("reason_code", "uint8"),
        ("reason_string", "string"),
    ]),
    5009: {},
    5010: {
        "addresses": ["address"]
    },
    5012: {
        "request_sent_time": "uint64"
    },
    5013: OrderedDict([
        ("request_sent_time", "uint64"),
        ("request_received_time", "uint64"),
        ("reply_transmitted_time", "uint64"),
    ]),
}

fetch_target = None

def block_respond(msg: dict, conn):
    if msg["block_id"] == fetch_target:
        conn.send(5003, {
            "item_type": 1001,
            "blockchain_synopsis": [fetch_target]
        })

def item_id_inventory_respond(msg: dict, conn):
    if msg["item_type"] == 1001:
        global fetch_target
        fetch_target = msg["item_hashes_available"][0]
        conn.send(5004, {
            "item_type": 1001,
            "items_to_fetch": [fetch_target]
        })
    else:
        conn.send(5004, {
            "item_type": 1000,
            "items_to_fetch": [msg["item_hashes_available"][0]]
        })

def blockchain_item_id_inventory_respond(msg: dict, conn):
    global fetch_target
    if fetch_target == msg["item_hashes_available"][-1]:
        return
    conn.send(5004, {
        "item_type": 1001,
        "items_to_fetch": msg["item_hashes_available"]
    })
    fetch_target = msg["item_hashes_available"][-1]

def fetch_item_id_respond(_, conn):
    conn.send(5002, {
        "item_type": 1001,
        "total_remaining_item_count": 0,
        "item_hashes_available": []
    })


def hello_respond(msg: dict, conn):
    key = ecdsa.recover_public_key(
              sha256(conn.shared_secret).digest(),
              bytes.fromhex(msg["signed_shared_secret"][2:]),
              0 if msg["signed_shared_secret"][0] == "1" else 1
          )
    res = bytes([3] if key.to_string()[63] % 2 == 1 else [2]) + key.to_string()[:32]
    if msg["node_public_key"] == res.hex():
        conn.send(5007, {})
        conn.send(5009, {})

def address_request_respond(_, conn):
    conn.send(5010, {
        "addresses": [{'direction': 1,
                 'firewalled': 1,
                 'last_seen_time': 1569070047,
                 'latency': 649791,
                 'node_id': PublicKey('d1e8e336b548f2d6be14f2e7d1f61dc47c072b930aa1c6fc62296d9c07bbc1bdcf'),
                 'remote_endpoint': '87.117.52.158:11206'}]
    })

def address_respond(_, conn):
    now = datetime.datetime.utcnow()
    conn.send(5012, {
        "request_sent_time": int(now.timestamp() * 1000000)
    })
    conn.send(5003, {
        "item_type": 1001,
        "blockchain_synopsis": ["027459d691393208e653d28b5592dc429de6f1dc"]
    })

def time_request_respond(msg: dict, conn):
    now = datetime.datetime.utcnow()
    conn.send(5013, {
        "request_sent_time": msg["request_sent_time"],
        "request_received_time": int(now.timestamp() * 1000000),
        "reply_transmitted_time": int(datetime.datetime.utcnow().timestamp() * 1000000)
    })

message_action_table = {
    1001: block_respond,
    5001: item_id_inventory_respond,
    5002: blockchain_item_id_inventory_respond,
    5003: fetch_item_id_respond,
    5006: hello_respond,
    5009: address_request_respond,
    5010: address_respond,
    5012: time_request_respond,
}

def parse_message(msg: bytes, conn):
    size = unpack("<I", msg[:4])[0]
    msg_type = unpack("<I", msg[4:8])[0]
    definition: OrderedDict = message_definition_table.get(msg_type, None)
    end = -(len(msg) - size - 8)
    if end == 0:
        end = None
    msg = msg[8:end]
    buf = Buffer()
    buf.write(msg)
    if definition is None:
        logging.warning("Unknown type of message: %d %s" % (msg_type, message_name_table.get(msg_type)))
    else:
        result = {}
        for name, type_ in definition.items():
            result[name] = unpack_field(buf, type_)
        if msg_type >= 5000:
            logging.info(pformat([message_name_table[msg_type], result]))
        elif msg_type == 1001:
            logging.info([message_name_table[msg_type], "Block %d" % unpack("!I", bytes.fromhex(result["block_id"][:8]))[0]])
        else:
            logging.info(pformat([message_name_table[msg_type], "Transaction"]))
        action = message_action_table.get(msg_type, None)
        if action is not None and conn is not None:
            action(result, conn)