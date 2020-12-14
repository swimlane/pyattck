import abc


class Base:

    def run(self):
        try:
            self.get()
        except:
            print('Failed running ')

    @abc.abstractmethod
    def get(self):
        pass
 