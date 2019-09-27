import logging
import socket
import threading
from hashlib import sha256, sha512
from struct import pack, unpack

import cityhash
from Cryptodome.Cipher import AES
# noinspection PyProtectedMember
from graphenebase import PublicKey as GraphenePublicKey, PrivateKey, ecdsa

from basic_types import String
from messages import parse_message, message_type_table
from utils import Buffer


class Connection:

    def __init__(self, ip, port):
        self.stream = Buffer()
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((ip, port))
        raw_pk = self.s.recv(33)
        self.pk = GraphenePublicKey(raw_pk.hex())
        sk = PrivateKey()
        point = self.pk.point() * int.from_bytes(bytes(sk), "big")
        x: int = point.x()
        raw_data = x.to_bytes(32, "big")
        self.shared_secret = sha512(raw_data).digest()
        key = sha256(self.shared_secret).digest()
        crc = cityhash.CityHash128(self.shared_secret)
        data = crc.to_bytes(16, "little")
        iv = data[8:16] + data[:8]
        self.s.sendall(bytes.fromhex(repr(sk.pubkey)))
        self.encryptor = AES.new(key, AES.MODE_CBC, iv)
        self.test = AES.new(key, AES.MODE_CBC, iv)
        self.decryptor = AES.new(key, AES.MODE_CBC, iv)
        self.worker_thread = threading.Thread(target=self.worker)
        self.worker_thread.start()
        self.send(5006, {
            "user_agent": "Haruka Mock Client",
            "core_protocol_version": 106,
            "inbound_address": "0.0.0.0",
            "inbound_port": 0,
            "outbound_port": 0,
            "node_public_key": sk.pubkey,
            "signed_shared_secret": ecdsa.sign_message(self.shared_secret, str(sk)),
            "chain_id": bytes.fromhex("4018d7844c78f6a6c41c6a552b898022310fc5dec06da467ee7905a8dad512c8"),
            "user_data": {
                "platform": String("unknown")
            }
        })

    def send(self, msg_type, data: dict):
        message_type = message_type_table[msg_type]
        message = message_type(data)
        res = message.pack()
        # for name, type_ in definition.items():
        #     res.extend(pack_field(data.get(name, None), type_))
        length = len(res)
        if length % 16 != 8:
            pad_length = (8 - length % 16)
            if pad_length < 0:
                pad_length += 16
            res += b"\x00" * pad_length
        res = pack("<II", length, msg_type) + res
        data = self.encryptor.encrypt(res)
        logging.debug("SEND >>> %s" % res)
        parse_message(res, None, 1)
        self.s.sendall(data)

    def worker(self):
        data = bytearray()
        while True:
            data.extend(self.s.recv(4096))
            if len(data) % 16 == 0:
                msg = self.decryptor.decrypt(bytes(data))
            else:
                continue
            data = bytearray()
            self.stream.write(msg)
            if len(msg) == 0:
                break
            logging.debug("RECV <<< %s" % msg)
            while self.stream.count():
                size = unpack("<I", self.stream.peek(4))[0]
                expect = size + 8 + (16 - (size + 8) % 16) % 16
                logging.debug("expect %s have %s" % (expect, self.stream.count()))
                if expect <= self.stream.count():
                    parse_message(self.stream.read(expect), self, 2)
                else:
                    break
