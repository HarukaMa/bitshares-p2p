import socket
import threading
from hashlib import sha256, sha512
from struct import pack, unpack

import cityhash
from Cryptodome.Cipher import AES
from graphenebase import PublicKey, PrivateKey, ecdsa

from .messages import parse_message, message_definition_table
from .pack import pack_field

class Connection:

    class Buffer:
        def __init__(self):
            self.buffer = bytearray()

        def write(self, data: bytes):
            self.buffer.extend(data)

        def read(self, size: int):
            data = self.buffer[:size]
            self.buffer[:size] = b""
            return data

        def peek(self, size: int):
            return self.buffer[:size]

        def count(self):
            return len(self.buffer)

        def __len__(self):
            return len(self.buffer)

    def __init__(self, ip, port):
        self.stream = self.Buffer()
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((ip, port))
        raw_pk = self.s.recv(33)
        self.pk = PublicKey(raw_pk.hex())
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
        self.send(5006, [
            "Haruka Mock Client",
            106,
            "0.0.0.0",
            0,
            0,
            sk.pubkey,
            ecdsa.sign_message(self.shared_secret, str(sk)),
            bytes.fromhex("4018d7844c78f6a6c41c6a552b898022310fc5dec06da467ee7905a8dad512c8"),
            {"platform": "unknown"
             }
        ])

    def send(self, type_, data):
        definition = message_definition_table.get(type_, None)
        if definition is None:
            print("Unknown message type", type_)
            return
        def_items = list(definition.items())
        res = bytearray()
        for i, item in enumerate(data):
            res += pack_field(def_items[i][1], item)
        length = len(res)
        if length % 16 != 8:
            pad_length = (8 - length % 16)
            if pad_length < 0:
                pad_length += 16
            res += b"\x00" * pad_length
        length = len(res)
        res = pack("<II", length, type_) + res
        data = self.encryptor.encrypt(res)
        print("SEND >>>", res)
        parse_message(res, None, True)
        self.s.sendall(data)

    def worker(self):
        data = bytearray()
        while True:
            data.extend(self.s.recv(65536))
            if len(data) % 16 == 0:
                msg = self.decryptor.decrypt(bytes(data))
            else:
                continue
            data = bytearray()
            self.stream.write(msg)
            if len(msg) == 0:
                break
            print("RECV <<<", msg)
            while self.stream.count():
                size = unpack("<I", self.stream.peek(4))[0]
                expect = size + 8 + (16 - (size + 8) % 16) % 16
                print("expect", expect, "have", self.stream.count())
                if expect <= self.stream.count():
                    parse_message(self.stream.read(expect), self)
                else:
                    break
