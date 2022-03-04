from .mobileattckobject import MobileAttckObject


class MobileAttckTechnique(MobileAttckObject):

    """Mobile MITRE ATT&CK Technique object.

    A child class of MobileAttckObject

    Creates objects which have been categorized as a technique used by attackers

    Each technique enables you to access the following properties on the object:

        1. command_list - A list of commands associated with a technique
        2. commands = A list of dictionary objects containing source, command, and
                      provided name associated with a technique
        3. queries = A list of dictionary objects containing product, query, and
                     name associated with a technique
        4. datasets = A list of raw datasets associated with a technique
        5. possible_detections = A list of raw datasets containing possible detection
                                 methods for a technique

    Example:
        You can iterate over an `techniques` list and access specific properties and
        relationship properties.

        The following relationship properties are accessible:
                1. tactics
                2. mitigations
                3. actors

            1. To iterate over an `techniques` list, do the following:

            .. code-block:: python

               from pyattck import Attck

               attck = Attck()

               for technique in attck.mobile.techniques:
                   print(technique.id)
                   print(technique.name)
                   print(technique.alias)
                   print(technique.description)
                   # etc.

            2. To access relationship properties, do the following:

            .. code-block:: python

               from pyattck import Attck

               attck = Attck()

               for technique in attck.mobile.techniques:
                   print(technique.id)
                   print(technique.name)
                   print(technique.alias)
                   print(technique.description)
                   # etc.

                   for malware in technique.malwares:
                       print(malware.name)
                       print(malware.description)
                       # etc.
    """

    def __init__(self, mobile_attck_obj = None, **kwargs):
        """
        Creates an MobileAttckTechnique object.  
        The MobileAttckTechnique object is a technique used by attackers.

        Arguments:
            attck_obj (json) -- Takes the raw MITRE Mobile ATT&CK Json object
            AttckObject (dict) -- Takes the MITRE Mobile ATT&CK Json object as a kwargs values
        """
        super(MobileAttckTechnique, self).__init__(**kwargs)
        self.__mobile_attck_obj = mobile_attck_obj
        self.old_attack_id = self._set_attribute(kwargs, 'x_mitre_old_attack_id')
        self.platforms = self._set_list_items(kwargs, 'x_mitre_platforms')
        self.version = self._set_attribute(kwargs, 'x_mitre_version')
        self.created_by_ref = self._set_attribute(kwargs, 'created_by_ref')
        self.contributor = self._set_list_items(kwargs, 'x_mitre_contributors')
        self.tactic_type = self._set_list_items(kwargs, 'x_mitre_tactic_type')
        self.external_reference = self._set_reference(kwargs)
        self.possible_detections = self._set_attribute(kwargs, 'x_mitre_detection')
        self.revoked = self._set_attribute(kwargs, 'revoked')
        self.wiki = self._set_wiki(kwargs)
        self.stix = self._set_attribute(kwargs, 'id')
        self.command_list = self.__get_filtered_dataset('command_list')
        self.commands = self.__get_filtered_dataset('commands')
        self.queries = self.__get_filtered_dataset('queries')
        self.datasets = self.__get_filtered_dataset('parsed_datasets')
        self.possible_detections = self.__get_filtered_dataset('possible_detections')
        self.tactics = kwargs
        self.set_relationships(self.__mobile_attck_obj)

    def __get_filtered_dataset(self, attribute_name):
        for item in MobileAttckObject.generated_attck_json['techniques']:
            if item['technique_id'] == self.id:
                return item[attribute_name]

    @property
    def tactics(self):
        """
        Accessing tactics that a specific technique belongs to as part
        of the MITRE Mobile ATT&CK Framework

        Returns:
            list: Returns all tactic objects as a list that a technique
                  belongs to
        """
        from .tactic import MobileAttckTactic
        tactic_list = []
        for item in self.__mobile_attck_obj['objects']:
            if 'x-mitre-tactic' in item['type']:
                for tact in self._tactic:
                    if str(tact).lower() == str(item['x_mitre_shortname']).lower():
                        tactic_list.append(MobileAttckTactic(mobile_attck_obj=self.__mobile_attck_obj, **item))
        return tactic_list

    @tactics.setter
    def tactics(self, obj):
        """
        Sets the associated tactic/phase this technique is in

        Arguments:
            obj (dict) -- A Mitre ATT&CK Framework json object

        Returns:
            (string) -- Returns a string that sets the tactic/phase this
                        technique is in. If there is no phase found, it
                        will return 'no phase_name'
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
        Accessing mitigiations for a specific technique as part of the
        MITRE Mobile ATT&CK Framework

        Returns:
            list: Returns all mitigation objects as a list that are associated
                  with a technique
        """
        from .mitigation import MobileAttckMitigation
        return_list = []
        item_dict = {}
        for item in self.__mobile_attck_obj['objects']:
            if 'type' in item:
                if item['type'] == 'course-of-action':
                    item_dict[item['id']] = item
        try:
            for item in self._RELATIONSHIPS[self.stix]:
                if item in item_dict:
                    return_list.append(MobileAttckMitigation(mobile_attck_obj=self.__mobile_attck_obj, **item_dict[item]))
        except:
            pass
        return return_list 

    @property
    def actors(self):
        """
        Accessing actors which have been identified as using a specific
        technique as part of the MITRE Mobile ATT&CK Framework

        Returns:
            list: Returns all actor objects as a list that are associated
                  with a technique
        """
        from .actor import MobileAttckActor
        return_list = []
        item_dict = {}
        for item in self.__mobile_attck_obj['objects']:
            if 'type' in item:
                if item['type'] == 'intrusion-set':
                    item_dict[item['id']] = item
        try:
            for item in self._RELATIONSHIPS[self.stix]:
                if item in item_dict:
                    return_list.append(MobileAttckActor(mobile_attck_obj=self.__mobile_attck_obj, **item_dict[item]))
        except:
            pass
        return return_list

    @property
    def tools(self):
        """
        Returns all tool objects that are used in a technique

        Returns:
            [list] -- A list of tool objects defined within the
                      Mobile MITRE ATT&CK Framework
        """
        from .tools import MobileAttckTools
        return_list = []
        item_dict = {}
        for item in self.__attck_obj['objects']:
            if 'type' in item:
                if item['type'] == 'tool':
                    item_dict[item['id']] = item
        if self._RELATIONSHIPS.get(self.stix):
            for item in self._RELATIONSHIPS.get(self.stix):
                if item in item_dict:
                    return_list.append(MobileAttckTools(attck_obj=self.__attck_obj, **item_dict[item]))
        return return_list

    @property
    def malwares(self):
        """
        Returns all malware objects that are used in a technique

        Returns:
            [list] -- A list of malware objects defined within the
                      Mobile MITRE ATT&CK Framework
        """
        from .malware import MobileAttckMalware
        return_list = []
        item_dict = {}
        for item in self.__mobile_attck_obj['objects']:
            if 'type' in item:
                if item['type'] == 'malware':
                    item_dict[item['id']] = item
        try:
            for item in self._RELATIONSHIPS[self.stix]:
                if item in item_dict:
                    return_list.append(MobileAttckMalware(mobile_attck_obj=self.__mobile_attck_obj, **item_dict[item]))
        except:
            pass
        return return_list
