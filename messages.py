import datetime
from collections import OrderedDict
from hashlib import sha256
from pprint import pprint
from struct import unpack

from graphenebase import ecdsa, PublicKey

from .pack import unpack_field

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

def time_request_respond(msg: dict, conn):
    now = datetime.datetime.utcnow()
    conn.send(5013, {
        "request_sent_time": msg["request_sent_time"],
        "request_received_time": int(now.timestamp() * 1000000),
        "reply_transmitted_time": int(datetime.datetime.utcnow().timestamp() * 1000000)
    })

message_action_table = {
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
    if definition is None:
        print("Unknown type of message:", msg_type, message_name_table.get(msg_type))
    else:
        result = {}
        for name, type_ in definition.items():
            result[name], msg = unpack_field(msg, type_)
        pprint([message_name_table[msg_type], result])
        action = message_action_table.get(msg_type, None)
        if action is not None and conn is not None:
            action(result, conn)