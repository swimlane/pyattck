
from .attckobject import AttckObject
from ..utils.logo import Logo
from ..utils.exceptions import GeneratedDatasetException
from ..datasets import AttckDatasets


class AttckActor(AttckObject):

    '''A child class of AttckObject
    
    Creates objects that are categorized as Mitre ATT&CK Enterprise Actors or Groups (e.g. APT1, APT32, etc.)

    You can also access external data properties. The following properties are generated using external data:

        1. country
        2. operations
        3. attribution_links
        4. known_tools
        5. targets
        6. additional_comments
        7. external_description

    You can retrieve the entire dataset using the `external_dataset` property.

    pyattck also enables you to retrieve or generate logos for the actor or group using the following properties:
        
        - ascii_logo - Generated ASCII logo based on the actor or groups name
        - image_logo - Generated ASCII logo based on a provided logo
    
    Example:
        You can iterate over an `actors` list and access specific properties and relationship properties.

        The following relationship properties are accessible:
                1. malwares
                2. tools
                3. techniques
        
            1. To iterate over an `actors` list, do the following:

            .. code-block:: python
               
               from pyattck import Attck

               attck = Attck()

               for actor in attck.enterprise.actors:
                   print(actor.id)
                   print(actor.name)
                   print(actor.aliases)
                   print(actor.description)
                   # etc.

            2. To access relationship properties, do the following:

            .. code-block:: python

               from pyattck import Attck

               attck = Attck()

               for actor in attck.enterprise.actors:
                   print(actor.id)
                   print(actor.name)
                   print(actor.aliases)
                   print(actor.description)

                   for malware in actor.enterprise.malwares:
                       print(malware.name)
                       print(malware.description)
                       # etc.

    Arguments:
        attck_obj (json) -- Takes the raw Mitre ATT&CK Json object
        AttckObject (dict) -- Takes the Mitre ATT&CK Json object as a kwargs values
    '''

    __ATTCK_DATASETS = None

    def __init__(self, attck_obj = None, **kwargs):
        super(AttckActor, self).__init__(**kwargs)
        self.attck_obj = attck_obj

        self.id = self._set_id(kwargs)
        self.created_by_ref = self._set_attribute(kwargs, 'created_by_ref')
        self.revoked = self._set_attribute(kwargs, 'revoked')
        self.name = self._set_attribute(kwargs, 'name')
        self.aliases = self._set_list_items(kwargs, 'aliases')
        self.description = self._set_attribute(kwargs, 'description')
        self.external_reference = self._set_reference(kwargs)
        self.created = self._set_attribute(kwargs, 'created')
        self.modified = self._set_attribute(kwargs, 'modified')
        self.stix = self._set_attribute(kwargs, 'id')
        self.type = self._set_attribute(kwargs, 'type')
        self.wiki = self._set_wiki(kwargs)
        self.contributor = self._set_list_items(kwargs, 'x_mitre_contributors')

        self.set_relationships(self.attck_obj)

        logo = Logo(self.name.strip().replace(' ','_').lower())
        self.ascii_logo = logo.get_ascii()
        self.image_logo = logo.get_image()

        if AttckActor.__ATTCK_DATASETS is None:
            try:
                data = AttckDatasets().generated_attck_data()
                if 'actors' in data:
                    AttckActor.__ATTCK_DATASETS = data['actors']
                self.external_dataset = self.__get_actors_dataset()
            except:
                raise GeneratedDatasetException('Unable to retrieve generated attack data properties')
            
        

    def __get_actors_dataset(self):
        return_list = []
        self.country = []
        self.operations = []
        self.attribution_links = []
        self.known_tools = []
        self.targets = []
        self.additional_comments = []
        self.external_description = []
        for country in AttckActor.__ATTCK_DATASETS:
            if country:
                for k,v in country.items():
                    for actor in v['actors']:
                        if 'names' in actor:
                            if actor['names']:
                                if self.name.lower() in actor['names']:
                                    self.country.append(k)
                                    return_list.append(actor)
                                    if 'operations' in actor:
                                        if actor['operations']:
                                            self.operations.append(actor['operations'])
                                    if 'links' in actor:
                                        if actor['links']:
                                            self.attribution_links.append(actor['links'])
                                    if 'tools' in actor:
                                        if actor['tools']:
                                            self.known_tools.append(actor['tools'])
                                    if 'targets' in actor:
                                        if actor['targets']:
                                            self.targets.append(actor['targets'])
                                    if 'comment' in actor:
                                        if actor['comment']:
                                            self.additional_comments.append(actor['comment'])
                                    if 'description' in actor:
                                        if actor['description']:
                                            self.external_description.append(actor['description'])
                            if self.aliases:
                                for alias in self.aliases:
                                    if alias.lower() in actor['names']:
                                        self.country.append(k)
                                        return_list.append(actor)
                                        if 'operations' in actor:
                                            if actor['operations']:
                                                self.operations.append(actor['operations'])
                                        if 'links' in actor:
                                            if actor['links']:
                                                self.attribution_links.append(actor['links'])
                                        if 'tools' in actor:
                                            if actor['tools']:
                                                self.known_tools.append(actor['tools'])
                                        if 'targets' in actor:
                                            if actor['targets']:
                                                self.targets.append(actor['targets'])
                                        if 'comment' in actor:
                                            if actor['comment']:
                                                self.additional_comments.append(actor['comment'])
                                        if 'description' in actor:
                                            if actor['description']:
                                                self.external_description.append(actor['description'])
        if return_list:
            return return_list
        else:
            return None


    @property
    def malwares(self):
        '''Returns all malware objects as a list that are documented as being used by an Actor or Group
        '''
        from .malware import AttckMalware
        return_list = []
        item_dict = {}
        for item in self.attck_obj['objects']:
            if 'type' in item:
                if item['type'] == 'malware':
                    item_dict[item['id']] = item
        
        for item in self._RELATIONSHIPS[self.stix]:
            if item in item_dict:
                return_list.append(AttckMalware(**item_dict[item]))
        return return_list

    @property
    def tools(self):
        '''Returns all tool object as a list that are documented as being used by an Actor or Group'''
        from .tools import AttckTools
        return_list = []
        item_dict = {}
        for item in self.attck_obj['objects']:
            if 'type' in item:
                if item['type'] == 'tool':
                    item_dict[item['id']] = item
        
        for item in self._RELATIONSHIPS[self.stix]:
            if item in item_dict:
                return_list.append(AttckTools(**item_dict[item]))
        return return_list

    @property
    def techniques(self):
        '''Returns all technique objects as a list that are documented as being used by an Actor or Group'''
        from .technique import AttckTechnique
        return_list = []
        item_dict = {}
        for item in self.attck_obj['objects']:
            if 'type' in item:
                if item['type'] == 'tool':
                    item_dict[item['id']] = item
        
        for item in self._RELATIONSHIPS[self.stix]:
            if item in item_dict:
                return_list.append(AttckTechnique(**item_dict[item]))
        return return_list
