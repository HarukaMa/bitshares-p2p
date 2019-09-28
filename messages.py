import datetime
import logging
from abc import abstractmethod
from collections import OrderedDict
from hashlib import sha256
from struct import unpack

from graphenebase import ecdsa

from basic_types import (
    RIPEMD160, Uint32, String, IPAddress, Uint16, Signature, SHA256, VariantObject, IPEndpoint, Uint8, Bool, Uint64,
    PublicKey)
from generic_types import Vector
from objectimpl import Address
from objects import Object
from operationimpl import SignedBlock, PrecomuutableTransaction
from utils import Buffer

ItemID = RIPEMD160

class Message(Object):

    @abstractmethod
    def message_id(self):
        pass

    def __repr__(self):
        return type(self).__name__

class TrxMessage(Message):

    message_id = 1000
    definition = {
        "trx": PrecomuutableTransaction
    }

    def __repr__(self):
        res = "Transaction, operations [ %s ]" % ", ".join(repr(x.data) for x in self["trx"]["operations"].data)
        return res

class BlockMessage(Message):

    message_id = 1001
    definition = OrderedDict([
        ("block", SignedBlock),
        ("block_id", ItemID)
    ])

    def __repr__(self):
        res = "Block %d, id %s, %d transactions" % (
            unpack(">I", self["block_id"].data[:4])[0],
            self["block_id"].data.hex(),
            len(self["block"]["transactions"].data)
        )
        return res

class ItemIDsInventoryMessage(Message):

    message_id = 5001
    definition = OrderedDict([
        ("item_type", Uint32),
        ("item_hashes_available", Vector[ItemID])
    ])

    def __repr__(self):
        if self["item_type"].data == 1001:
            return "Have %d new block" % len(self["item_hashes_available"].data)
        elif self["item_type"].data == 1000:
            return "Have %d new transaction" % len(self["item_hashes_available"].data)



class BlockchainItemIDsInventoryMessage(Message):

    message_id = 5002
    definition = OrderedDict([
        ("total_remaining_item_count", Uint32),
        ("item_type", Uint32),
        ("item_hashes_available", Vector[ItemID])
    ])

    def __repr__(self):
        items = self["item_hashes_available"].data
        if len(items) == 0:
            return "Have no blocks available"
        return "Have %d blocks, sending hashes for block %d - %d" % (
            self["total_remaining_item_count"].data + len(items),
            unpack(">I", items[0].data[:4])[0],
            unpack(">I", items[-1].data[:4])[0]
        )

class FetchBlockchainItemIDsMessage(Message):

    message_id = 5003
    definition = OrderedDict([
        ("item_type", Uint32),
        ("blockchain_synopsis", Vector[ItemID])
    ])

    def __repr__(self):
        return "Fetch blocks, last known block is %d" % unpack(">I", self["blockchain_synopsis"].data[0].data[:4])[0]

class FetchItemsMessage(Message):

    message_id = 5004
    definition = OrderedDict([
        ("item_type", Uint32),
        ("items_to_fetch", Vector[ItemID])
    ])

    def __repr__(self):
        if self["item_type"].data == 1001:
            return "Fetch block %d - %d" % (
                unpack(">I", self["items_to_fetch"].data[0].data[:4])[0],
                unpack(">I", self["items_to_fetch"].data[-1].data[:4])[0]
            )
        elif self["item_type"].data == 1000:
            return "Fetch transaction %s" % self["items_to_fetch"].data[0].data.hex()

class ItemNotAvailableMessage(Message):

    message_id = 5005
    definition = {
        "requested_item": ItemID
    }

class HelloMessage(Message):

    message_id = 5006
    definition = OrderedDict([
        ("user_agent", String),
        ("core_protocol_version", Uint32),
        ("inbound_address", IPAddress),
        ("inbound_port", Uint16),
        ("outbound_port", Uint16),
        ("node_public_key", PublicKey),
        ("signed_shared_secret", Signature),
        ("chain_id", SHA256),
        ("user_data", VariantObject)
    ])

    def __repr__(self):
        if self["user_agent"].data == "Haruka Mock Client":
            return "Hello from mock client"
        res = "Hello from %s:%d running %s (%s), head block %d on %s" % (
            self["inbound_address"].data, self["inbound_port"].data, self["user_agent"].data,
            self["user_data"].data["fc_git_revision_sha"].data.data[:7],
            self["user_data"].data["last_known_block_number"].data.data,
            self["user_data"].data["last_known_block_time"].data.data
        )
        return res

class ConnectionAcceptedMessage(Message):

    message_id = 5007
    definition = {}

    def __repr__(self):
        return "Connection accepted"

class ConnectionRejectedMessage(Message):

    message_id = 5008
    definition = OrderedDict([
        ("user_agent", String),
        ("core_protocol_version", Uint32),
        ("remote_endpoint", IPEndpoint),
        ("reason_code", Uint8),
        ("reason_string", String)
    ])

class AddressRequestMessage(Message):

    message_id = 5009
    definition = {}

    def __repr__(self):
        return "Request node list"

class AddressMessage(Message):

    message_id = 5010
    definition = {
        "addresses": Vector[Address]
    }

    def __repr__(self):
        res = "Known nodes: [\n  "
        res += "\n  ".join(map(repr, self["addresses"].data))
        return res + "\n]"

class ClosingConnectionMessage(Message):

    message_id = 5011
    definition = OrderedDict([
        ("reason_for_closing", String),
        ("closing_due_to_error", Bool),
        ("error", ""),
    ])

class CurrentTimeRequestMessage(Message):

    message_id = 5012
    definition = {
        "request_sent_time": Uint64
    }

    def __repr__(self):
        return "Request current time"

class CurrentTimeReplyMessage(Message):

    message_id = 5013
    definition = OrderedDict([
        ("request_sent_time", Uint64),
        ("request_received_time", Uint64),
        ("reply_transmitted_time", Uint64)
    ])

    def __repr__(self):
        return "Current time is %f" % (self["reply_transmitted_time"].data / 1000000)

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
    5099: "core_message_type"
}

message_type_table = {
    1000: TrxMessage,
    1001: BlockMessage,
    5001: ItemIDsInventoryMessage,
    5002: BlockchainItemIDsInventoryMessage,
    5003: FetchBlockchainItemIDsMessage,
    5004: FetchItemsMessage,
    5005: ItemNotAvailableMessage,
    5006: HelloMessage,
    5007: ConnectionAcceptedMessage,
    5008: ConnectionRejectedMessage,
    5009: AddressRequestMessage,
    5010: AddressMessage,
    5011: ClosingConnectionMessage,
    5012: CurrentTimeRequestMessage,
    5013: CurrentTimeReplyMessage,
    5014: None,
    5015: None,
    5016: None,
    5017: None,
}

fetch_target = None

def block_respond(msg: Message, conn):
    if msg["block_id"].data == fetch_target:
        conn.send(5003, {
            "item_type": 1001,
            "blockchain_synopsis": [fetch_target]
        })

def item_id_inventory_respond(msg: Message, conn):
    if msg["item_type"] == 1001:
        global fetch_target
        fetch_target = msg["item_hashes_available"].data[0].data
        conn.send(5004, {
            "item_type": 1001,
            "items_to_fetch": [fetch_target]
        })
    else:
        conn.send(5004, {
            "item_type": 1000,
            "items_to_fetch": [msg["item_hashes_available"].data[0].data]
        })

def blockchain_item_id_inventory_respond(msg: Message, conn):
    global fetch_target
    if fetch_target == msg["item_hashes_available"].data[-1].data:
        return
    conn.send(5004, {
        "item_type": 1001,
        "items_to_fetch": msg["item_hashes_available"].data
    })
    fetch_target = msg["item_hashes_available"].data[-1].data

def fetch_item_id_respond(_, conn):
    conn.send(5002, {
        "item_type": 1001,
        "total_remaining_item_count": 0,
        "item_hashes_available": []
    })

def hello_respond(msg: Message, conn):
    key = ecdsa.recover_public_key(
              sha256(conn.shared_secret).digest(),
              msg["signed_shared_secret"].data[1:],
              0 if msg["signed_shared_secret"].data[0] == 31 else 1
          )
    res = bytes([3] if key.to_string()[63] % 2 == 1 else [2]) + key.to_string()[:32]
    if repr(msg["node_public_key"].data) == res.hex():
        conn.send(5007, {})
        conn.send(5009, {})

def address_request_respond(_, conn):
    conn.send(5010, {
        "addresses": []
    })

def address_respond(_, conn):
    now = datetime.datetime.utcnow()
    conn.send(5012, {
        "request_sent_time": int(now.timestamp() * 1000000)
    })
    conn.send(5003, {
        "item_type": 1001,
        "blockchain_synopsis": ["02773f092a07e75c930921dc20e8edc7ab85b887"]
    })


def time_request_respond(msg: Message, conn):
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

def parse_message(msg: bytes, conn, dir_):
    size = unpack("<I", msg[:4])[0]
    msg_type = unpack("<I", msg[4:8])[0]
    message_type = message_type_table[msg_type]
    end = -(len(msg) - size - 8)
    if end == 0:
        end = None
    msg = msg[8:end]
    buf = Buffer()
    buf.write(msg)
    message = message_type.unpack(buf)
    logging.info(("\033[36mSEND >>> \033[0m" if dir_ == 1 else "\033[32mRECV <<< \033[0m") + repr(message))
    action = message_action_table.get(msg_type, None)
    if action is not None and conn is not None:
        action(message, conn)