from .attckobject import AttckObject


class AttckTechnique(AttckObject):

    """Enterprise MITRE ATT&CK Technique object.

    A child class of AttckObject

    Creates objects which have been categorized as a technique used by attackers

    Each technique enables you to access the following properties on the object:

        1. command_list - A list of commands associated with a technique
        2. commands = A list of dictionary objects containing source, command,
                      and provided name associated with a technique
        3. queries = A list of dictionary objects containing product, query,
                     and name associated with a technique
        4. datasets = A list of raw datasets associated with a technique
        5. possible_detections = A list of raw datasets containing possible
                                 detection methods for a technique

    Example:
        You can iterate over an `techniques` list and access specific
        properties and relationship properties.

        The following relationship properties are accessible:
                1. tactics
                2. mitigations
                3. actors
                4. tools
                5. malwares
                6. controls
                7. data_components
                8. data_sources

            1. To iterate over an `techniques` list, do the following:

            .. code-block:: python

               from pyattck import Attck

               attck = Attck()

               for technique in attck.enterprise.techniques:
                   print(technique.id)
                   print(technique.name)
                   print(technique.alias)
                   print(technique.description)
                   # etc.

            2. To access relationship properties, do the following:

            .. code-block:: python

               from pyattck import Attck

               attck = Attck()

               for technique in attck.enterprise.techniques:
                   print(technique.id)
                   print(technique.name)
                   print(technique.alias)
                   print(technique.description)
                   # etc.

                   for malware in technique.malwares:
                       print(malware.name)
                       print(malware.description)
                       # etc.

                   # to get a count of controls for a technique do the following
                   print(len(technique.controls))

                   # below will print each controls properties & values
                   for control in technique.controls:
                       print(control.__dict__)

                   # below will print the id, name and description of a control
                   for control in technique.controls:
                       print(control.id)
                       print(control.name)
                       print(control.description)

    Arguments:
        attck_obj (json) -- Takes the raw MITRE ATT&CK Json object
        AttckObject (dict) -- Takes the MITRE ATT&CK Json object as a kwargs values
    """

    def __init__(self, attck_obj = None, **kwargs):
        """
        This class represents a Technique as defined by the
        Enterprise MITRE ATT&CK framework.

        Keyword Arguments:
            attck_obj {json} -- A Enterprise MITRE ATT&CK Framework
                                json object (default: {None})

        Raises:
            GeneratedDatasetException: Raised an exception when unable to
                                       access or process the external
                                       generated dataset.
        """
        super(AttckTechnique, self).__init__(**kwargs)
        self.__attck_obj = attck_obj
        self.created_by_reference = self._set_attribute(kwargs, 'created_by_ref')
        self.platforms = self._set_list_items(kwargs, 'x_mitre_platforms')
        self.permissions = self._set_list_items(kwargs, 'x_mitre_permissions_required')
        self.bypass = self._set_list_items(kwargs, 'x_mitre_defense_bypassed')
        self.effective_permissions = self._set_list_items(kwargs, 'x_mitre_effective_permissions')
        self.network = self._set_attribute(kwargs, 'x_mitre_network_requirements')
        self.remote = self._set_attribute(kwargs, 'x_mitre_remote_support')
        self.system_requirements = self._set_attribute(kwargs, 'x_mitre_system_requirements')
        self.detection = self._set_attribute(kwargs, 'x_mitre_detection')
        self.__data_sources = self._create_data_sources_dict(kwargs.get('x_mitre_data_sources'))
        self.created = self._set_attribute(kwargs, 'created')
        self.modified = self._set_attribute(kwargs, 'modified')
        self.__subtechniques = []
        self.wiki = self._set_wiki(kwargs)
        self.contributors = self._set_list_items(kwargs, 'x_mitre_contributors')
        self.revoked = self._set_attribute(kwargs, 'revoked')
        self.subtechnique = False if self._set_attribute(kwargs, 'x_mitre_is_subtechnique') is None else True
        self.__subtechniques = []
        self.command_list = self.__get_filtered_dataset('command_list')
        self.commands = self.__get_filtered_dataset('commands')
        self.queries = self.__get_filtered_dataset('queries')
        self.datasets = self.__get_filtered_dataset('parsed_datasets')
        self.possible_detections = self.__get_filtered_dataset('possible_detections')
        self.tactics = kwargs
        self.set_relationships(self.__attck_obj)

    def __get_filtered_dataset(self, attribute_name):
        for item in AttckObject.generated_attck_json['techniques']:
            if item['technique_id'] == self.id:
                return item[attribute_name]

    def __get_subtechnique_id(self, obj):
        return obj.id

    @property
    def subtechniques(self):
        """
        Subtechniques are by default nested under their parent technique.
        To flatten all techniques onto the same level provide
        nested_subtechniques=False when instantiating the Attck object.

        Returns:
            [type]: [description]
        """
        return sorted(self.__subtechniques, key=self.__get_subtechnique_id)

    @subtechniques.setter
    def subtechniques(self, value):
        self.__subtechniques.append(value)

    @property
    def controls(self):
        """
        Returns all compliance control objects that are associated with a technique

        Returns:
            [list] -- A list of control objects defined within the
                      Enterprise MITRE ATT&CK Framework
        """
        from .control import AttckControl
        control_list = []
        if AttckObject.generated_nist_json.get(self.stix):
            if AttckObject.nist_controls_json.get('objects'):
                for control in AttckObject.nist_controls_json['objects']:
                    if control.get('id') in AttckObject.generated_nist_json[self.stix]:
                        control_list.append(AttckControl(**control))
        return control_list

    @property
    def data_components(self):
        from .datasource import AttckDataComponent
        return_list = []
        item_dict = {}
        for item in self.__attck_obj['objects']:
            if 'type' in item:
                if item['type'] == 'x-mitre-data-component':
                    item_dict[item['id']] = item
        if self._RELATIONSHIPS.get(self.stix):
            for item in self._RELATIONSHIPS[self.stix]:
                if item in item_dict:
                    return_list.append(AttckDataComponent(**item_dict[item]))
        return return_list 

    @property
    def data_sources(self):
        """
        Returns all data source objects that a technique belongs to

        Returns:
            [list] -- A list of data source objects defined within the
                      Enterprise MITRE ATT&CK Framework
        """
        from .datasource import AttckDataSource
        data_source_list = []
        for item in self.__attck_obj['objects']:
            if 'x-mitre-data-source' in item['type'] and self.__data_sources.get(item['name']):
                data_source_list.append(AttckDataSource(
                    attck_obj=self.__attck_obj, 
                    _data_component_filter=self.__data_sources[item['name']],
                    **item)
                )
        return data_source_list

    @property
    def tactics(self):
        """
        Returns all tactic object that a technique belongs to

        Returns:
            [list] -- A list of tactic objects defined within the
                      Enterprise MITRE ATT&CK Framework
        """
        from .tactic import AttckTactic
        tactic_list = []
        for item in self.__attck_obj['objects']:
            if 'x-mitre-tactic' in item['type']:
                for tact in self._tactic:
                    if str(tact).lower() == str(item['x_mitre_shortname']).lower():
                        tactic_list.append(AttckTactic(attck_obj=self.__attck_obj, **item))
        return tactic_list

    @tactics.setter
    def tactics(self, obj):
        """
        Sets the associated tactic/phase this technique is in

        Arguments:
            obj (dict) -- A MITRE ATT&CK Framework json object

        Returns:
            (string) -- Returns a string that sets the tactic/phase this technique is in. 
                        If there is no phase found, it will return 'no phase_name'
        """
        temp_list = []
        try:
            for phase in obj['kill_chain_phases']:
                temp_list.append(phase['phase_name'])
            self._tactic = temp_list
        except:
            self._tactic = ['no phase_name']
        
    @property
    def mitigations(self):
        """
        Returns all mitigation objects that a technique is associated with

        Returns:
            [list] -- A list of mitigation objects defined within the
                      Enterprise MITRE ATT&CK Framework
        """
        from .mitigation import AttckMitigation
        return_list = []
        item_dict = {}
        for item in self.__attck_obj['objects']:
            if 'type' in item:
                if item['type'] == 'course-of-action':
                    item_dict[item['id']] = item
        if self._RELATIONSHIPS.get(self.stix):
            for item in self._RELATIONSHIPS[self.stix]:
                if item in item_dict:
                    return_list.append(AttckMitigation(attck_obj=self.__attck_obj, **item_dict[item]))
        return return_list 

    @property
    def actors(self):
        """
        Returns all actor objects that use a technique

        Returns:
            [list] -- A list of actor objects defined within the
                      Enterprise MITRE ATT&CK Framework
        """
        from .actor import AttckActor
        return_list = []
        item_dict = {}
        for item in self.__attck_obj['objects']:
            if 'type' in item:
                if item['type'] == 'intrusion-set':
                    item_dict[item['id']] = item
        if self._RELATIONSHIPS.get(self.stix):
            for item in self._RELATIONSHIPS[self.stix]:
                if item in item_dict:
                    return_list.append(AttckActor(attck_obj=self.__attck_obj, **item_dict[item]))
        return return_list

    @property
    def tools(self):
        """
        Returns all tool objects that are used in a technique

        Returns:
            [list] -- A list of tool objects defined within the
                      Enterprise MITRE ATT&CK Framework
        """
        from .tools import AttckTools
        return_list = []
        item_dict = {}
        for item in self.__attck_obj['objects']:
            if 'type' in item:
                if item['type'] == 'tool':
                    item_dict[item['id']] = item
        if self._RELATIONSHIPS.get(self.stix):
            for item in self._RELATIONSHIPS.get(self.stix):
                if item in item_dict:
                    return_list.append(AttckTools(attck_obj=self.__attck_obj, **item_dict[item]))
        return return_list

    @property
    def malwares(self):
        """
        Returns all malware objects that are used in a technique

        Returns:
            [list] -- A list of malware objects defined within the
                      Enterprise MITRE ATT&CK Framework
        """
        from .malware import AttckMalware
        return_list = []
        item_dict = {}
        for item in self.__attck_obj['objects']:
            if 'type' in item:
                if item['type'] == 'malware':
                    item_dict[item['id']] = item
        if self._RELATIONSHIPS.get(self.stix):
            for item in self._RELATIONSHIPS.get(self.stix):
                if item in item_dict:
                    return_list.append(AttckMalware(attck_obj=self.__attck_obj, **item_dict[item]))
        return return_list
