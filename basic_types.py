import re
from abc import ABCMeta, abstractmethod
from struct import pack, unpack

# noinspection PyProtectedMember
from graphenebase import PublicKey as GraphenePublicKey

from utils import Buffer


class Serializable(metaclass=ABCMeta):

    @staticmethod
    @abstractmethod
    def unpack(msg: Buffer):
        pass

    @abstractmethod
    def pack(self):
        pass

class JSONSerializable(metaclass=ABCMeta):

    # @staticmethod
    # @abstractmethod
    # def json_deserialize(msg: any):
    #     pass

    # returns a object which could be put into json.dumps(), not actual json string
    # easier to run through every member
    @abstractmethod
    def json_object(self):
        pass

# Basic types

class VarInt(Serializable, JSONSerializable):
    def __init__(self, data):
        if type(data) is not int:
            raise TypeError("Unsupported type %s, expected int" % type(data).__name__)
        if data < 0 or data > 0xffffffffffffffff:
            raise ValueError("Value does not fit in uint64")
        self.data = data

    @staticmethod
    def unpack(msg: Buffer):
        value = 0
        i = 0
        while True:
            byte = ord(msg.read(1))
            value += (byte & 0x7f) << (i * 7)
            if byte & 0x80 != 0x80:
                break
            i += 1
        return value

    def pack(self):
        res = bytearray()
        data = self.data
        while True:
            v = data & 0x7f
            if data - 128 > 0:
                v |= 0x80
            res.append(v)
            data >>= 7
            if data == 0:
                break
        return res

    def __repr__(self):
        return str(self.data)

    def json_object(self):
        return self.data

class String(Serializable, JSONSerializable):
    def __init__(self, data):
        if type(data) is not str:
            raise TypeError("Unsupported type %s, expected str" % type(data).__name__)
        self.data = data

    @staticmethod
    def unpack(msg: Buffer):
        length = VarInt.unpack(msg)
        return String((msg.read(length)).decode("utf8"))

    def pack(self):
        res = VarInt(len(self.data)).pack()
        res.extend(self.data.encode("utf8"))
        return res

    def __repr__(self):
        return self.data

    def json_object(self):
        return self.data

class Data(Serializable, JSONSerializable):
    # maps to c++ vector<char> as this type have special json serialization
    def __init__(self, data):
        if type(data) is bytes:
            self.data = data
        elif type(data) is bytearray:
            self.data = bytes(data)
        else:
            raise TypeError("Unsupported type %s, expected bytes-like object" % type(data).__name__)

    @staticmethod
    def unpack(msg: Buffer):
        length = VarInt.unpack(msg)
        return Data(msg.read(length))

    def pack(self):
        # TODO: implement
        raise NotImplementedError

    def __repr__(self):
        return self.data.hex()

    def json_object(self):
        return self.data.hex()

class Bool(Serializable, JSONSerializable):
    def __init__(self, data):
        if type(data) is not bool:
            raise TypeError("Unsupported type %s, expected bool" % type(data).__name__)
        self.data = data

    @staticmethod
    def unpack(msg: Buffer):
        return Bool(True) if ord(msg.read(1)) == True else Bool(False)

    def pack(self):
        return bytearray([1 if self.data else 0])

    def __repr__(self):
        return "True" if self.data else "False"

    def json_object(self):
        return True if self.data else False


class Uint8(Serializable, JSONSerializable):
    def __init__(self, data):
        if type(data) is not int:
            raise TypeError("Unsupported type %s, expected int" % type(data).__name__)
        if data < 0 or data > 255:
            raise ValueError("Value does not fit in uint8")
        self.data = data

    @staticmethod
    def unpack(msg: Buffer):
        return Uint8(ord(msg.read(1)))

    def pack(self):
        return bytearray([self.data])

    def __repr__(self):
        return str(self.data)

    def json_object(self):
        return self.data

class Uint16(Serializable, JSONSerializable):
    def __init__(self, data):
        if type(data) is not int:
            raise TypeError("Unsupported type %s, expected int" % type(data).__name__)
        if data < 0 or data > 0xffff:
            raise ValueError("Value does not fit in uint16")
        self.data = data

    @staticmethod
    def unpack(msg: Buffer):
        return Uint16(unpack("<H", msg.read(2))[0])

    def pack(self):
        return pack("<H", self.data)

    def __repr__(self):
        return str(self.data)

    def json_object(self):
        return self.data

class Uint32(Serializable, JSONSerializable):
    def __init__(self, data):
        if type(data) is not int:
            raise TypeError("Unsupported type %s, expected int" % type(data).__name__)
        if data < 0 or data > 0xffffffff:
            raise ValueError("Value does not fit in uint32")
        self.data = data

    @staticmethod
    def unpack(msg: Buffer):
        return Uint32(unpack("<I", msg.read(4))[0])

    def pack(self):
        return pack("<I", self.data)

    def __repr__(self):
        return str(self.data)

    def json_object(self):
        return self.data

class Uint64(Serializable, JSONSerializable):
    def __init__(self, data):
        if type(data) is not int:
            raise TypeError("Unsupported type %s, expected int" % type(data).__name__)
        if data < 0 or data > 0xffffffffffffffff:
            raise ValueError("Value does not fit in uint64")
        self.data = data

    @staticmethod
    def unpack(msg: Buffer):
        return Uint64(unpack("<Q", msg.read(8))[0])

    def pack(self):
        return pack("<Q", self.data)

    def __repr__(self):
        return str(self.data)

    def json_object(self):
        return self.data

class Int64(Serializable, JSONSerializable):
    def __init__(self, data):
        if type(data) is not int:
            raise TypeError("Unsupported type %s, expected int" % type(data).__name__)
        if data < -0x8000000000000000 or data > 0x7fffffffffffffff:
            raise ValueError("Value does not fit in int64")
        self.data = data

    @staticmethod
    def unpack(msg: Buffer):
        return Int64(unpack("<q", msg.read(8))[0])

    def pack(self):
        return pack("<q", self.data)

    def __repr__(self):
        return str(self.data)

    def json_object(self):
        return self.data

class IPAddress(Serializable, JSONSerializable):
    # Saved as string internally
    def __init__(self, data):
        if type(data) is not str:
            raise TypeError("Unsupported type %s, expected str" % type(data).__name__)
        if re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", data) is None:
            raise ValueError("IP address is not valid")
        self.data = data

    @staticmethod
    def unpack(msg: Buffer):
        data = msg.read(4)
        return IPAddress("%s.%s.%s.%s" % (data[3], data[2], data[1], data[0]))

    def pack(self):
        msg = list(map(int, self.data.split(".")))
        return bytearray([msg[3], msg[2], msg[1], msg[0]])

    def __repr__(self):
        return self.data

    def json_object(self):
        return self.data

class IPEndpoint(Serializable, JSONSerializable):
    # Saved as string internally
    def __init__(self, data):
        if type(data) is not str:
            raise TypeError("Unsupported type %s, expected str" % type(data).__name__)
        if re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):\d+", data) is None:
            raise ValueError("IP endpoint is not valid")
        try:
            port = int(data.split(":")[1])
        except ValueError:
            raise ValueError("Port is not valid")
        if port <= 0 or port > 65535:
            raise ValueError("Port is not valid")

        self.data = data

    @staticmethod
    def unpack(msg: Buffer):
        data = msg.read(6)
        return IPEndpoint("%s.%s.%s.%s:%s" % (data[3], data[2], data[1], data[0], unpack("<H", data[4:6])[0]))

    def pack(self):
        msg = list(map(int, re.split(r"[:.]", self.data)))
        res = bytearray([msg[3], msg[2], msg[1], msg[0]])
        res.extend(pack("<H", msg[4]))
        return res

    def __repr__(self):
        return self.data

    def json_object(self):
        return self.data

class FakePublicKey(Serializable, JSONSerializable):
    # for node_ids which is actually random 33 bytes
    def __init__(self, data):
        if type(data) is bytes:
            self.data = data
        elif type(data) is bytearray:
            self.data = bytes(data)
        else:
            raise TypeError("Unsupported type %s, expected bytes-like object" % type(data).__name__)

    @staticmethod
    def unpack(msg: Buffer):
        return FakePublicKey(msg.read(33))

    def pack(self):
        return bytearray(self.data)

    def __repr__(self):
        return self.data.hex()

    def json_object(self):
        return self.data.hex()

class PublicKey(Serializable, JSONSerializable):
    # wraps around graphenebase pubkey
    def __init__(self, data):
        if type(data) is GraphenePublicKey:
            self.data = data
        else:
            raise TypeError("Unsupported type %s, expected graphenebase PublicKey" % type(data).__name__)

    @staticmethod
    def unpack(msg: Buffer):
        data = msg.read(33)
        return PublicKey(GraphenePublicKey(data.hex(), prefix="BTS"))

    def pack(self):
        return bytearray(bytes(self.data))

    def __repr__(self):
        return repr(self.data)

    def json_object(self):
        return str(self.data)

class Signature(Serializable, JSONSerializable):
    # save as bytes
    def __init__(self, data):
        if type(data) is bytes:
            self.data = data
        elif type(data) is bytearray:
            self.data = bytes(data)
        else:
            raise TypeError("Unsupported type %s, expected bytes-like object" % type(data).__name__)

    @staticmethod
    def unpack(msg: Buffer):
        return Signature(msg.read(65))

    def pack(self):
        return self.data

    def __repr__(self):
        return self.data.hex()

    def json_object(self):
        return self.data.hex()

class SHA1(Serializable, JSONSerializable):

    def __init__(self, data):
        if type(data) is bytes:
            self.data = data
        elif type(data) is bytearray:
            self.data = bytes(data)
        else:
            raise TypeError("Unsupported type %s, expected bytes-like object" % type(data).__name__)

    @staticmethod
    def unpack(msg: Buffer):
        return SHA1(msg.read(20))

    def pack(self):
        return self.data

    def __repr__(self):
        return self.data.hex()

    def json_object(self):
        return self.data.hex()

class SHA256(Serializable, JSONSerializable):

    def __init__(self, data):
        if type(data) is bytes:
            self.data = data
        elif type(data) is bytearray:
            self.data = bytes(data)
        else:
            raise TypeError("Unsupported type %s, expected bytes-like object" % type(data).__name__)

    @staticmethod
    def unpack(msg: Buffer):
        return SHA256(msg.read(32))

    def pack(self):
        return self.data

    def __repr__(self):
        return self.data.hex()

    def json_object(self):
        return self.data.hex()
    
class RIPEMD160(Serializable, JSONSerializable):
    # only used as item id and address
    def __init__(self, data):
        if type(data) is bytes:
            self.data = data
        elif type(data) is bytearray:
            self.data = bytes(data)
        elif type(data) is str:
            self.data = bytes.fromhex(data)
        else:
            raise TypeError("Unsupported type %s, expected bytes-like object" % type(data).__name__)

    @staticmethod
    def unpack(msg: Buffer):
        return RIPEMD160(msg.read(20))

    def pack(self):
        return self.data

    def __repr__(self):
        return self.data.hex()

    def json_object(self):
        return self.data.hex()

class VoteID(Serializable, JSONSerializable):

    def __init__(self, *args):
        if len(args) == 1:
            if type(args[0]) is str:
                parts = args[0].split(":")
                self.type = int(parts[0])
                self.instance = int(parts[1])
            else:
                raise TypeError("Unsupported type %s, expected str" % type(args[0]).__name__)
        elif len(args) == 2:
            if all(type(x) is int for x in args):
                self.type = args[0]
                self.instance = args[1]
            else:
                raise TypeError("Arguments must be ints")

    @staticmethod
    def unpack(msg: Buffer):
        value = unpack("<I", msg.read(4))[0]
        type_ = value & 0xff
        instance = (value & 0xffffff00) >> 8
        return VoteID(type_, instance)

    def pack(self):
        # TODO: implement
        raise NotImplementedError

    def __repr__(self):
        return "%d:%d" % (self.type, self.instance)

    def json_object(self):
        return repr(self)


class VariantObject(Serializable, JSONSerializable):
    # dict string:any, enforce string
    def __init__(self, data: dict):
        if type(data) is not dict:
            raise TypeError("Unsupported type %s, expected dict" % type(data).__name__)
        if not all(type(x) is str or type(x) is String for x in data.keys()):
            raise TypeError("Keys must be str")
        if not all(type(y) in Variant.allowed_types for y in data.values()):
            raise TypeError("Values must be able to be converted to Variant")
        self.data = {}
        for key, value in data.items():
            self.data[key] = Variant(value)

    @staticmethod
    def unpack(msg: Buffer):
        obj = {}
        count = VarInt.unpack(msg)
        for _ in range(count):
            key = String.unpack(msg).data
            index = ord(msg.read(1))
            type_ = Variant.allowed_types[index]
            value = type_.unpack(msg)
            obj[key] = value
        return VariantObject(obj)

    def pack(self):
        res = VarInt(len(self.data)).pack()
        for k, v in self.data.items():
            res.extend(String(k).pack())
            res.extend(v.pack())
        return res

    def __getitem__(self, item):
        return self.data[item]

    def __setitem__(self, key, value):
        if type(key) is not str:
            raise TypeError("Keys must be str")
        self.data[key] = value

    def __repr__(self):
        return str(self.data)

    def json_object(self):
        return dict((k, v.json_object()) for k, v in self.data.items())

class Null(Serializable, JSONSerializable):

    @staticmethod
    def unpack(_):
        return Null()

    def pack(self):
        return bytearray()

    def __repr__(self):
        return "null"

    def json_object(self):
        return None

class Variant(Serializable, JSONSerializable):

    allowed_types = [
        Null,
        Null, # Int64
        Uint64,
        Null, # Double
        Null, # Bool
        String,
        Null, # Array
        VariantObject,
        Null, # Blob
    ]

    def __init__(self, data):
        # TODO: array (Vector[Variant]) may need additional logic
        if type(data) not in self.allowed_types:
            raise TypeError("Unsupported type %s for Variant" % type(data))
        self.data = data

    @staticmethod
    def unpack(msg: Buffer):
        # TODO: Legit todo
        pass

    def pack(self):
        # TODO: array (Vector[Variant]) may need additional logic
        index = VarInt(self.allowed_types.index(type(self.data)))
        res = index.pack()
        res.extend(self.data.pack())
        return res

    def __repr__(self):
        return str(self.data)

    def json_object(self):
        return self.data.json_object()

