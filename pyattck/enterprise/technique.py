from .attckobject import AttckObject
from ..datasets import AttckDatasets
from ..utils.exceptions import GeneratedDatasetException

class AttckTechnique(AttckObject):
    '''A child class of AttckObject
    
    Creates objects which have been categorized as a technique used by attackers
    
    Each technique enables you to access the following properties on the object:

        1. command_list - A list of commands associated with a technique
        2. commands = A list of dictionary objects containing source, command, and provided name associated with a technique
        3. queries = A list of dictionary objects containing product, query, and name associated with a technique
        4. datasets = A list of raw datasets associated with a technique
        5. possible_detections = A list of raw datasets containing possible detection methods for a technique


    Example:
        You can iterate over an `techniques` list and access specific properties and relationship properties.

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
                   print(technique.aliases)
                   print(technique.description)
                   # etc.

            2. To access relationship properties, do the following:

            .. code-block:: python

               from pyattck import Attck

               attck = Attck()

               for technique in attck.techniques:
                   print(technique.id)
                   print(technique.name)
                   print(technique.aliases)
                   print(technique.description)
                   # etc.

                   for malware in technique.malwares:
                       print(malware.name)
                       print(malware.description)
                       # etc.

    Arguments:
        attck_obj (json) -- Takes the raw Mitre ATT&CK Json object
        AttckObject (dict) -- Takes the Mitre ATT&CK Json object as a kwargs values
    '''

    __LOCAL_FOLDER_PATH = None
    __ATTCK_DATASETS = None

    def __init__(self, attck_obj = None, **kwargs):
        """Creates an AttckTechnique object.  
           The AttckTechnique object is a technique used by attackers.
        """
        super(AttckTechnique, self).__init__(**kwargs)
        self.attck_obj = attck_obj

        self.created_by_reference = self._set_attribute(kwargs, 'created_by_ref')
        self.platforms = self._set_list_items(kwargs, 'x_mitre_platforms')
        self.permissions = self._set_list_items(kwargs, 'x_mitre_permissions_required')
        self.bypass = self._set_list_items(kwargs, 'x_mitre_defense_bypassed')
        self.effective_permissions = self._set_list_items(kwargs, 'x_mitre_effective_permissions')
        self.network = self._set_attribute(kwargs, 'x_mitre_network_requirements')
        self.remote = self._set_attribute(kwargs, 'x_mitre_remote_support')
        self.system_requirements = self._set_attribute(kwargs, 'x_mitre_system_requirements')
        self.detection = self._set_attribute(kwargs, 'x_mitre_detection')
        self.data_source = self._set_list_items(kwargs, 'x_mitre_data_sources')
        self.created = self._set_attribute(kwargs, 'created')
        self.modified = self._set_attribute(kwargs, 'modified')

        self.wiki = self._set_wiki(kwargs)
        self.contributor = self._set_attribute(kwargs, 'contributor')

        if AttckTechnique.__ATTCK_DATASETS is None:
            try:
                AttckTechnique.__ATTCK_DATASETS = AttckDatasets().generated_attck_data()
            except:
                raise GeneratedDatasetException('Unable to retrieve generated attack data properties')

        self.command_list = self.__get_filtered_dataset(self.id, 'command_list')
        self.commands = self.__get_filtered_dataset(self.id, 'commands')
        self.queries = self.__get_filtered_dataset(self.id, 'queries')
        self.datasets = self.__get_filtered_dataset(self.id, 'parsed_datasets')
        self.possible_detections = self.__get_filtered_dataset(self.id, 'possible_detections')

        self.tactics = kwargs

        self.set_relationships(self.attck_obj)

    def __get_filtered_dataset(self, technique_id, attribute_name):
        for item in AttckTechnique.__ATTCK_DATASETS['techniques']:
            if item['technique_id'] == technique_id:
                return item[attribute_name]

    @property
    def tactics(self):
        '''Returns all tactics as a list that this technique is found in'''
        from .tactic import AttckTactic
        tactic_list = []
        for item in self.attck_obj['objects']:
            if 'x-mitre-tactic' in item['type']:
                for tact in self._tactic:
                    if str(tact).lower() == str(item['x_mitre_shortname']).lower():
                        tactic_list.append(AttckTactic(**item))
        return tactic_list
            

    @tactics.setter
    def tactics(self, obj):
        """Sets the associated tactic/phase this technique is in
        
        Arguments:
            obj (dict) -- A Mitre ATT&CK Framework json object
        
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
        '''Returns all mitigation objects as a list that are documented to help mitigate the current technique object'''
        from .mitigation import AttckMitigation
        return_list = []
        item_dict = {}
        for item in self.attck_obj['objects']:
            if 'type' in item:
                if item['type'] == 'mitigates':
                    item_dict[item['id']] = item
        try:
            for item in self._RELATIONSHIPS[self.stix]:
                if item in item_dict:
                    return_list.append(AttckMitigation(**item_dict[item]))
        except:
            pass
        return return_list 

    @property
    def actors(self):
        '''Returns all actor objects that have been identified as using this technique'''
        from .actor import AttckActor
        return_list = []
        item_dict = {}
        for item in self.attck_obj['objects']:
            if 'type' in item:
                if item['type'] == 'intrusion-set':
                    item_dict[item['id']] = item
        try:
            for item in self._RELATIONSHIPS[self.stix]:
                if item in item_dict:
                    return_list.append(AttckActor(**item_dict[item]))
        except:
            pass
        return return_list