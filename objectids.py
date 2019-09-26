from abc import ABCMeta, abstractmethod
from struct import unpack

from basic_types import Serializable, VarInt
from utils import Buffer


class ObjectID(Serializable, metaclass=ABCMeta):

    def __init__(self, data):
        if type(data) is VarInt:
            self.id = data.data
            return
        if type(data) is not int:
            raise TypeError("Unsupported type %s, expected int" % type(data).__name__)
        self.id = data

    @abstractmethod
    def space(self):
        pass

    @abstractmethod
    def type(self):
        pass

    @classmethod
    def unpack(cls, msg: Buffer):
        return cls(VarInt.unpack(msg))

    def pack(self):
        return VarInt(self.id).pack()


class FullObjectID(Serializable, metaclass=ABCMeta):

    # noinspection PyMethodOverriding
    @staticmethod
    def unpack(msg: Buffer):
        data = unpack("<Q", msg.read(8))[0]
        type_ = (data & (0xff << 48)) >> 48
        id_ = data & 0xffffffffffff
        return FullObjectID.oid_types[type_](id_)


class AccountID(ObjectID, FullObjectID):

    space = 1
    type = 2

class AssetID(ObjectID, FullObjectID):

    space = 1
    type = 3

class ForceSettlementID(ObjectID, FullObjectID):

    space = 1
    type = 4

class CommitteeMemberID(ObjectID, FullObjectID):

    space = 1
    type = 5

class WitnessID(ObjectID, FullObjectID):

    space = 1
    type = 6

class LimitOrderID(ObjectID, FullObjectID):

    space = 1
    type = 7

class CallOrderID(ObjectID, FullObjectID):

    space = 1
    type = 8

class CustomID(ObjectID, FullObjectID):

    space = 1
    type = 9

class ProposalID(ObjectID, FullObjectID):

    space = 1
    type = 10

class OperationHistoryID(ObjectID, FullObjectID):

    space = 1
    type = 11

class WithdrawPermissionID(ObjectID, FullObjectID):

    space = 1
    type = 12

class VestingBalanceID(ObjectID, FullObjectID):

    space = 1
    type = 13

class WorkerID(ObjectID, FullObjectID):

    space = 1
    type = 14

FullObjectID.oid_types = {
    2: AccountID,
    3: AssetID,
    4: ForceSettlementID,
    5: CommitteeMemberID,
    6: WitnessID,
    7: LimitOrderID,
    8: CallOrderID,
    9: CustomID,
    10: ProposalID,
    11: OperationHistoryID,
    12: WithdrawPermissionID,
    13: VestingBalanceID,
    14: WorkerID,
}