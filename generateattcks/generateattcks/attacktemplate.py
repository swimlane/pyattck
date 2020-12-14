

class AttackTemplate(object):

    def __init__(self):
        self._id = None
        self.command_list = []
        self.commands = []
        self.parsed_datasets = []
        self.attack_paths = []
        self.possible_query_list = []
        self.detection_data_source_list = []
        self.external_reference = []
        self.c2_data = []
        self.actor_data = []
        self.tool_data = []

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        self._id = self.__convert_to_utf8(value)

    def get(self):
        return_dict = {}
        if self.id:
            return_dict['technique_id'] = self.id
        if self.commands:
            return_dict['commands'] = self.commands
        if self.parsed_datasets:
            return_dict['parsed_datasets'] = self.parsed_datasets
        if self.command_list:
            return_dict['command_list'] = list(set(self.command_list))
        if self.attack_paths:
            return_dict['attack_paths'] = self.attack_paths
        if self.possible_query_list:
            return_dict['queries'] = self.possible_query_list
        if self.detection_data_source_list:
            return_dict['possible_detections'] = self.detection_data_source_list
        if self.c2_data:
            return_dict['c2_data'] = self.c2_data
        if self.actor_data:
            return_dict['actors'] = self.actor_data
        if self.tool_data:
            return_dict['tools'] = self.tool_data
        if self.external_reference:
            return_dict['external_reference'] = self.external_reference
        return return_dict

    def add_command(self, source, command, name=None):
        if command:
            self.command_list.append(self.__convert_to_utf8(command.strip()))
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

    def add_external_reference(self, reference):
        self.external_reference.append(reference)

    def add_detection_data_sources(self, data_source):
        self.detection_data_source_list.append({
            'data_source': data_source
        })

    def add_c2_data(self, name, value):
        self.c2_data.append({
            'name': name,
            'data': value
        })

    def add_actor_data(self, names, targets, operations, description, tools, links, attck_id=None, comment=None):
        self.actor_data.append({
            'names': names,
            'targets': targets,
            'operations': operations,
            'description': description,
            'tools': tools,
            'links': links,
            'attck_id': attck_id,
            'comment': comment
        })

    def add_malware_tools_data(self, name, family, comment, links):
        self.tool_data.append({
            'names': name,
            'family': family,
            'comments': comment,
            'links': links
        })

    def __convert_to_utf8(self, value):
        try:
            return str(value.encode('utf-8').decode('ascii', 'ignore'))
        except:
            return value
