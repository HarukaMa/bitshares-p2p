from abc import abstractmethod

from objects import Object


class Operation(Object):

    @abstractmethod
    def opid(self):
        pass

