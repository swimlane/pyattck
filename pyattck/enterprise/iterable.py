
class IterableMetaClass(type):
    def get_instances(cls):
        for instance in cls._instances:
            yield instance
        for subclass in cls.__subclasses__():
            for instance in subclass.get_instances():
                yield instance

    def __iter__(cls):
        return cls.get_instances()

    def __len__(cls):
        return len(list(cls.get_instances()))

    def __init__(cls, name, bases, nmspc):
        super().__init__(name, bases, nmspc)
        cls._instances = []

class Iterable(object, metaclass=IterableMetaClass):
    def _delete_instance(self):
        self.__class__._instances.remove(self)

    def __init__(self):
        self._instances.append(self)

