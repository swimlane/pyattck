

class AttackTemplate(object):

    def __init__(self):
        self.command_list = []
        self.commands = []
        self.parsed_datasets = []
        self.attack_paths = []
        self.possible_query_list = []

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        self._id = self.__convert_to_utf8(value)

    def get(self):
        return_dict = {}
        return_dict['technique_id'] = self.id
        if self.commands:
            return_dict['commands'] = self.commands
        if self.parsed_datasets:
            return_dict['parsed_datasets'] = self.parsed_datasets
        if self.command_list:
            return_dict['command_list'] = self.command_list
        if self.attack_paths:
            return_dict['attack_paths'] = self.attack_paths
        if self.possible_query_list:
            return_dict['queries'] = self.possible_query_list
        return return_dict

    def add_command(self, source, command, name=None):
        self.command_list.append(self.__convert_to_utf8(command))
        self.commands.append({
            'source': self.__convert_to_utf8(source),
            'command': self.__convert_to_utf8(command),
            'name': None if name is None else self.__convert_to_utf8(name)
        })

    def add_dataset(self, name, data):
        self.parsed_datasets.append({
            self.__convert_to_utf8(name): self.__convert_to_utf8(data)
        })

    def add_attack_path(self, name, description, phases):
        self.attack_paths.append({
            'name': name,
            'description': description,
            'phases': phases
        })

    def add_possible_queries(self, product, query, name=None):
        self.possible_query_list.append({
            'product': product,
            'query': query,
            'name': name
        })

    def __convert_to_utf8(self, value):
        try:
            return str(value.encode('utf-8').decode('ascii', 'ignore'))
        except:
            return value