class Search:

    def __init__(self, actors, malwares, mitigations, tactics, techniques, tools):
        self.__actors = actors
        self.__malwares = malwares
        self.__mitigations = mitigations
        self.__tactics = tactics
        self.__techniques = techniques
        self.__tools = tools

    def __search(self, kwargs, iterator):
        return_set = set()
        for item in iterator:
            for key,val in kwargs.items():
                if hasattr(item, key) and getattr(item, key):
                    if isinstance(getattr(item, key), list):
                        for i in getattr(item, key):
                            if val in i:
                                return_set.add(item.__repr__())
                    elif isinstance(getattr(item, key), dict):
                        for k,v in getattr(item, key).items():
                            if val in k or val in v:
                                return_set.add(item.__repr__())
                    else:
                        if val in getattr(item, key).lower():
                            return_set.add(item.__repr__())
        return list(return_set)

    def __print_help(self, iterator):
        key_list = []
        for key,val in iterator[0].__dict__.items():
            if not key.startswith('_'):
                key_list.append(key)
        print('Please provide one or more parameters when searching.',
            f'You can provide any property avaible on an object. {key_list}')

    def actors(self, **kwargs):
        if not kwargs:
            self.__print_help(self.__actors)
        return self.__search(kwargs, self.__actors)

    def malwares(self, **kwargs):
        if not kwargs:
            self.__print_help(self.__actors)
        return self.__search(kwargs, self.__malwares)

    def mitigations(self, **kwargs):
        if not kwargs:
            self.__print_help(self.__actors)
        return self.__search(kwargs, self.__mitigations)

    def tactics(self, **kwargs):
        if not kwargs:
            self.__print_help(self.__actors)
        return self.__search(kwargs, self.__tactics)

    def techniques(self, **kwargs):
        if not kwargs:
            self.__print_help(self.__actors)
        return self.__search(kwargs, self.__techniques)

    def tools(self, **kwargs):
        if not kwargs:
            self.__print_help(self.__actors)
        return self.__search(kwargs, self.__tools)
