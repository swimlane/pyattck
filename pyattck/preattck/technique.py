from .preattckobject import PreAttckObject


class PreAttckTechnique(PreAttckObject):

    """MITRE PRE-ATT&CK Technique object.

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
        You can iterate over an `techniques` list and access specific properties
        and relationship properties.

        The following relationship properties are accessible:
                1. tactics
                2. mitigations
                3. actors

            1. To iterate over an `techniques` list, do the following:

            .. code-block:: python

               from pyattck import Attck

               attck = Attck()

               for technique in attck.techniques:
                   print(technique.id)
                   print(technique.name)
                   print(technique.alias)
                   print(technique.description)
                   # etc.

            2. To access relationship properties, do the following:

            .. code-block:: python

               from pyattck import Attck

               attck = Attck()

               for technique in attck.techniques:
                   print(technique.id)
                   print(technique.name)
                   print(technique.alias)
                   print(technique.description)
                   # etc.

                   for malware in technique.malwares:
                       print(malware.name)
                       print(malware.description)
                       # etc.

    Arguments:
        attck_obj (json) -- Takes the raw Mitre ATT&CK Json object
        AttckObject (dict) -- Takes the Mitre ATT&CK Json object as a kwargs values
    """

    def __init__(self, preattck_obj = None, **kwargs):
        """
        This class represents a Techniques as defined by the
        MITRE PRE-ATT&CK framework.

        Keyword Arguments:
            preattck_obj {json} -- A MITRE PRE-ATT&CK Framework
                                   json object (default: {None})
        """
        super(PreAttckTechnique, self).__init__(**kwargs)
        self.__preattck_obj = preattck_obj
        self.old_attack_id = self._set_attribute(kwargs, 'x_mitre_old_attack_id')
        self.common_defenses = self._set_attribute(kwargs, 'x_mitre_detectable_by_common_defenses_explanation')
        self.tactics = kwargs
        self.version = self._set_attribute(kwargs, 'x_mitre_version')
        self.difficult = self._set_attribute(kwargs, 'x_mitre_difficulty_for_adversary')
        self.difficulty_reason = self._set_attribute(kwargs, 'x_mitre_difficulty_for_adversary_explanation')
        self.created_by_reference = self._set_attribute(kwargs, 'created_by_ref')
        self.detectable = self._set_attribute(kwargs, 'x_mitre_detectable_by_common_defenses')
        self.possible_detections = self._set_attribute(kwargs, 'x_mitre_detectable_by_common_defenses_explanation')
        self.deprecated = self._set_attribute(kwargs, 'x_mitre_deprecated')
        self.stix = self._set_attribute(kwargs, 'id')
        self.wiki = self._set_wiki(kwargs)
        self.command_list = self.__get_filtered_dataset('command_list')
        self.commands = self.__get_filtered_dataset('commands')
        self.queries = self.__get_filtered_dataset('queries')
        self.datasets = self.__get_filtered_dataset('parsed_datasets')
        self.possible_detections = self.__get_filtered_dataset('possible_detections')
        self.set_relationships(self.__preattck_obj)

    def __get_filtered_dataset(self, attribute_name):
        for item in PreAttckObject.generated_attck_json['techniques']:
            if item['technique_id'] == self.id:
                return item[attribute_name]

    @property
    def tactics(self):
        """
        Accessing tactics a specific technique belongs to based
        on the MITRE PRE-ATT&CK Framework

        Returns:
            list: Returns all tactic objects as a techinque belongs to
        """
        from .tactic import PreAttckTactic
        tactic_list = []
        for item in self.__preattck_obj['objects']:
            if 'x-mitre-tactic' in item['type']:
                for tact in self._tactic:
                    if str(tact).lower() == str(item['x_mitre_shortname']).lower():
                        tactic_list.append(PreAttckTactic(preattck_obj=self.__preattck_obj, **item))
        return tactic_list

    @tactics.setter
    def tactics(self, obj):
        """
        Sets the associated tactic/phase this technique is in

        Arguments:
            obj (dict) -- A MITRE PRE-ATT&CK Framework json object

        Returns:
            (string) -- Returns a string that sets the tactic/phase this technique
                        is in. If there is no phase found, it will return 'no phase_name'
        """
        temp_list = []
        try:
            for phase in obj['kill_chain_phases']:
                temp_list.append(phase['phase_name'])
            self._tactic = temp_list
        except:
            self._tactic = ['no phase_name']

    @property
    def actors(self):
        """
        Accessing actors who are known to use a specific technique
        as part of the MITRE PRE-ATT&CK Framework

        Returns:
            list: Returns all actor objects as a list that are
                  documented as using a technique
        """
        from .actor import PreAttckActor
        return_list = []
        item_dict = {}
        for item in self.__preattck_obj['objects']:
            if 'type' in item:
                if item['type'] == 'intrusion-set':
                    item_dict[item['id']] = item
        try:
            for item in self._RELATIONSHIPS[self.stix]:
                if item in item_dict:
                    return_list.append(PreAttckActor(preattck_obj=self.__preattck_obj, **item_dict[item]))
        except:
            pass
        return return_list
