from abc import ABCMeta, abstractmethod

from basic_types import (
    Serializable, JSONSerializable)
from utils import Buffer


# noinspection PyUnresolvedReferences
class Object(Serializable, JSONSerializable, metaclass=ABCMeta):

    def __init__(self, *args):
        if len(args) > 1:
            raise ValueError("Too many arguments")
        if len(args) == 1:
            if type(args[0]) is not dict:
                raise TypeError("Unsupported type %s, expected dict" % type(args[0]).__name__)
            self.__dict__.update(args[0])

    @abstractmethod
    def definition(self):
        pass

    @classmethod
    def unpack(cls, msg: Buffer):
        res = cls()
        for name, type_ in cls.definition.items():
            setattr(res, name, type_.unpack(msg))
        return res

    def pack(self):
        res = bytearray()
        for name, type_ in self.definition.items():
            value = getattr(self, name)
            if type(value) is type_:
                res.extend(value.pack())
            else:
                res.extend(type_(value).pack())
        return res

    def __getitem__(self, item):
        return getattr(self, item)

    def __setitem__(self, item, value):
        return setattr(self, item, value)

    def __repr__(self):
        return type(self).__name__

    def json_object(self):
        res = {}
        for k in self.definition.keys():
            if type(self[k]) is dict:
                res[k] = self[k]
            else:
                res[k] = self[k].json_object()
        return res
