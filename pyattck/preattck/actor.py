from .preattckobject import PreAttckObject
from ..utils.logo import Logo
from ..utils.exceptions import GeneratedDatasetException
from ..datasets import AttckDatasets


class PreAttckActor(PreAttckObject):

    '''A child class of PreAttckObject
    
    Creates objects that are categorized as MITRE PRE-ATT&CK Actors or Groups (e.g. APT1, APT32, etc.)

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
    
    Example:
        You can iterate over an `actors` list and access specific properties and relationship properties.

        The following relationship properties are accessible:
                
                1. techniques
        
            1. To iterate over an `actors` list, do the following:

            .. code-block:: python
               
               from pyattck import Attck

               attck = Attck()

               for actor in attck.preattack.actors:
                   print(actor.id)
                   print(actor.name)
                   print(actor.alias)
                   print(actor.description)
                   # etc.

            2. To access relationship properties, do the following:

            .. code-block:: python

               from pyattck import Attck

               attck = Attck()

               for actor in attck.preattack.actors:
                   print(actor.id)
                   print(actor.name)
                   print(actor.alias)
                   print(actor.description)

                   for technique in actor.techniques:
                       print(technique.name)
                       print(technique.description)
                       # etc.
    '''

    __PREATTCK_DATASETS = None

    def __init__(self, preattck_obj = None, **kwargs):
        """Creates objects that are categorized as MITRE PRE-ATT&CK Actors or Groups (e.g. APT1, APT32, etc.)

        Arguments:
            attck_obj (json) -- Takes the raw MITRE PRE-ATT&CK Json object
            AttckObject (dict) -- Takes the MITRE PRE-ATT&CK Json object as a kwargs values

        Raises:
            GeneratedDatasetException: Error when accessing third-party generated datasets
        """
        super(PreAttckActor, self).__init__(**kwargs)
        self.__preattck_obj = preattck_obj

        self.created_by_ref = self._set_attribute(kwargs, 'created_by_ref')
        self.version = self._set_attribute(kwargs, 'x_mitre_version')
        self.name = self._set_attribute(kwargs, 'name')
        self.external_reference = self._set_reference(kwargs)
        self.stix = self._set_attribute(kwargs, 'id')
        self.contributor = self._set_list_items(kwargs, 'x_mitre_contributors')
        self.wiki = self._set_wiki(kwargs)
        
        self.set_relationships(self.__preattck_obj)

        logo = Logo(self.name.strip().replace(' ','_').lower())
        self.ascii_logo = logo.get_ascii()
        
        if PreAttckActor.__PREATTCK_DATASETS is None:
            try:
                data = AttckDatasets().generated_attck_data()
                if 'actors' in data:
                    PreAttckActor.__PREATTCK_DATASETS = data['actors']
            except:
                raise GeneratedDatasetException('Unable to retrieve generated attack data properties')
            
        self.external_dataset = self.__get_actors_dataset()
        

    def __get_actors_dataset(self):
        return_list = []
        self.country = []
        self.operations = []
        self.attribution_links = []
        self.known_tools = []
        self.targets = []
        self.additional_comments = []
        self.external_description = []
        for country in PreAttckActor.__PREATTCK_DATASETS:
            if country:
                for k,v in country.items():
                    for actor in v['actors']:
                        if 'names' in actor:
                            if actor['names']:
                                if self.name in actor['names']:
                                    if k not in self.country:
                                        self.country.append(k)
                                    return_list.append(actor)
                                    if 'operations' in actor:
                                        if actor['operations']:
                                            for operation in actor['operations']:
                                                if operation not in self.operations:
                                                    self.operations.append(operation)
                                    if 'links' in actor:
                                        if actor['links']:
                                            for link in actor['links']:
                                                if link not in self.attribution_links:
                                                    self.attribution_links.append(link)
                                    if 'tools' in actor:
                                        if actor['tools']:
                                            for tool in actor['tools']:
                                                if tool not in self.known_tools:
                                                    self.known_tools.append(tool)
                                    if 'targets' in actor:
                                        if actor['targets']:
                                            if actor['targets'] not in self.targets:
                                                self.targets.append(actor['targets'])
                                    if 'comment' in actor:
                                        if actor['comment']:
                                            if actor['comment'] not in self.additional_comments:
                                                self.additional_comments.append(actor['comment'])
                                    if 'description' in actor:
                                        if actor['description']:
                                            if actor['description'] not in self.external_description:
                                                self.external_description.append(actor['description'])
                            if self.alias:
                                for alias in self.alias:
                                    if alias in actor['names']:
                                        if k not in self.country:
                                            self.country.append(k)
                                        return_list.append(actor)
                                        if 'operations' in actor:
                                            if actor['operations']:
                                                for operation in actor['operations']:
                                                    if operation not in self.operations:
                                                        self.operations.append(operation)
                                        if 'links' in actor:
                                            if actor['links']:
                                                for link in actor['links']:
                                                    if link not in self.attribution_links:
                                                        self.attribution_links.append(link)
                                        if 'tools' in actor:
                                            if actor['tools']:
                                                for tool in actor['tools']:
                                                    if tool not in self.known_tools:
                                                        self.known_tools.append(tool)
                                        if 'targets' in actor:
                                            if actor['targets']:
                                                if actor['targets'] not in self.targets:
                                                    self.targets.append(actor['targets'])
                                        if 'comment' in actor:
                                            if actor['comment']:
                                                if actor['comment'] not in self.additional_comments:
                                                    self.additional_comments.append(actor['comment'])
                                        if 'description' in actor:
                                            if actor['description']:
                                                if actor['description'] not in self.external_description:
                                                    self.external_description.append(actor['description'])
        if return_list:
            return return_list
        else:
            return None


    @property
    def techniques(self):
        """Accessing an actors known techniques as part of the MITRE PRE-ATT&CK Framework

        Returns:
            list: Returns all technique objects as a list that are documented as being used by an Actor or Group
        """
        from .technique import PreAttckTechnique
        return_list = []
        item_dict = {}
        for item in self.__preattck_obj['objects']:
            if 'type' in item:
                if item['type'] == 'attack-pattern':
                    item_dict[item['id']] = item
        
        for item in self._RELATIONSHIPS[self.stix]:
            if item in item_dict:
                return_list.append(PreAttckTechnique(**item_dict[item]))
        return return_list