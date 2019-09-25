

from abc import ABCMeta, abstractmethod
from collections import OrderedDict

from basic_types import Serializable, VarInt
from utils import Buffer

# Generic types

# Subscripting the type itself returns a instance of the type with type attribute set.
# Further calls imitate __init__ by setting the actual data.
# Try to convert to designated type and rely on lower-level exceptions.


class GenericType(metaclass=ABCMeta):
    @abstractmethod
    def __init__(self, types):
        self.types = types

    def __class_getitem__(cls, item):
        if not isinstance(item, tuple):
            item = item,
        if not all(isinstance(x, type) or isinstance(x, GenericType) for x in item):
            raise TypeError
        return cls(item)

class Vector(Serializable, GenericType):
    def __init__(self, types):
        if len(types) != 1:
            raise TypeError("Vector should only have 1 type")
        if not isinstance(types[0], type) and not isinstance(types[0], GenericType):
            raise TypeError("Argument must be type")
        super().__init__(types)

    # enforce same type of items
    def __call__(self, data):
        if type(data) is not list:
            raise TypeError("Unsupported type %s, expected list" % type(data).__name__)
        self.data = []
        for item in data:
            if isinstance(item, self.types[0]):
                self.data.append(item)
            else:
                self.data.append(self.types[0](item))
        return self

    def unpack(self, msg: Buffer):
        obj = []
        count = VarInt.unpack(msg)
        for _ in range(count):
            obj.append(self.types[0].unpack(msg))
        return obj

    def pack(self):
        res = VarInt(len(self.data)).pack()
        for i in self.data:
            res.extend(i.pack())
        return res

class Map(Serializable, GenericType):
    def __init__(self, types):
        if len(types) != 2:
            raise TypeError("Map should have 2 types")
        if not all(isinstance(t, type) for t in types):
            raise TypeError("Arguments must be types")
        super().__init__(types)

    # only accepting dict at the moment
    def __call__(self, data):
        if type(data) is not dict:
            raise TypeError("Unsupported type %s, expected dict" % type(data).__name__)
        if not all(isinstance(x, self.types[0]) for x in data.keys()):
            raise TypeError("All keys must be of type %s" % self.types[0].__name__)
        if not all(isinstance(x, self.types[1]) for x in data.values()):
            raise TypeError("All values must be of type %s" % self.types[1].__name__)
        self.data = {}
        for k, v in data.items():
            self.data[k] = v
        return self

    def unpack(self, msg: Buffer):
        obj = {}
        count = VarInt.unpack(msg)
        for _ in range(count):
            key = self.types[0].unpack(msg)
            value = self.types[1].unpack(msg)
            obj[key] = value
        return self(obj)

    def pack(self):
        res = VarInt(len(self.data)).pack()
        for k, v in self.data.items():
            res.extend(k.pack())
            res.extend(v.pack())
        return res


class Optional(Serializable, GenericType):
    def __init__(self, types):
        if len(types) != 1:
            raise TypeError("Optional should only have 1 type")
        if not isinstance(types[0], type):
            raise TypeError("Argument must be type")
        super().__init__(types)

    def __call__(self, data):
        if data is None:
            self.null = True
            self.data = None
        else:
            self.null = False
            if isinstance(data, self.types[0]):
                self.data = data
            else:
                self.data = self.types[0](data)
        return self

    def unpack(self, msg: Buffer):
        null = ord(msg.read(1))
        if null == 0:
            return self(None)
        else:
            return self(self.types[0].unpack(msg))

    def pack(self):
        if self.null:
            return bytearray([0])
        else:
            res = bytearray([1])
            res.extend(self.data.pack())
            return res

class Extension(Serializable, GenericType):
    # extension relies on the structure definition of Object to work
    def __init__(self, types):
        if len(types) != 1:
            raise TypeError("Extension should only have 1 type")
        from objects import Object
        if not issubclass(types[0], Object):
            raise TypeError("Unsupported type %s, expected Object" % types[0])
        super().__init__(types)

    def __call__(self, data):
        if type(data) is not self.types[0]:
            raise TypeError("Unsupported type %s, expected %s" % (type(data), self.types[0]))
        self.data = data
        return self

    def unpack(self, msg: Buffer):
        definition: OrderedDict = self.types[0].definition
        length = VarInt.unpack(msg)
        items = list(definition.items())
        res = self.types[0]()
        for _ in range(length):
            index = VarInt.unpack(msg)
            setattr(res, items[index][0], items[index][1].unpack(msg))
        return self(res)

    def pack(self):
        definition: OrderedDict = self.types[0].definition
        values = []
        for i, item in enumerate(definition.items()):
            value = getattr(self.data, item[0], None)
            if value is not None:
                values.append((i, value))
        res = VarInt(len(values)).pack()
        for i, v in values:
            res.extend(VarInt(i).pack())
            res.extend(v.pack())
        return res

class StaticVariant(Serializable, GenericType):
    # types take a list of possible types, there is no limit on it
    def __init__(self, types):
        if not all(isinstance(x, type) for x in types):
            raise TypeError("Arguments must be types")
        super().__init__(types)

    def __call__(self, data):
        for i, t in enumerate(self.types):
            if isinstance(data, t) or type(data) is t:
                self.type = i
                self.data = data
                return self
        raise TypeError(
            "%s is not in allowed types: %s" % (type(data).__name__, list(map(lambda x: x.__name__, self.types))))

    def unpack(self, msg: Buffer):
        index = VarInt.unpack(msg)
        return self(self.types[index].unpack(msg))

    def pack(self):
        res = VarInt(self.type).pack()
        res.extend(self.data.pack())

