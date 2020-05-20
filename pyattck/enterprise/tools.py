from .attckobject import AttckObject
from ..datasets import AttckDatasets
from ..utils.exceptions import GeneratedDatasetException


class AttckTools(AttckObject):
    '''
        A child class of AttckObject
    
        Creates objects which have been categorized as tools or software which have been categorized as software used in attacks
        
        You can also access external data properties. The following properties are generated using external data:

            1. additional_names
            2. attribution_links
            3. additional_comments
            4. family

        You can retrieve the entire dataset using the `external_dataset` property.

        You can also access external data properties from the C2 Matrix project. The following properties are generated using C2 Matrix external data:

            - HTTP
            - Implementation
            - Custom Profile
            - DomainFront
            - Multi-User
            - SMB
            - Kill Date
            - macOS
            - GitHub
            - Key Exchange
            - Chaining
            - Price
            - TCP
            - Proxy Aware
            - HTTP3
            - HTTP2
            - Date
            - Evaluator
            - Working Hours
            - Slack
            - FTP
            - Version Reviewed
            - Logging
            - Name
            - License
            - Windows
            - Stego
            - Notes
            - Server
            - Actively Maint.
            - Dashboard
            - DNS
            - Popular Site
            - ICMP
            - IMAP
            - DoH
            - Jitter
            - How-To
            - ATT&CK Mapping
            - Kali
            - Twitter
            - MAPI
            - Site
            - Agent
            - API
            - UI
            - Linux

        You can retrieve the entire dataset using the `c2_data` property.


        Example:
            You can iterate over an `tools` list and access specific properties and relationship properties.

            The following relationship properties are accessible:
                    1. techniques
                    2. actors
            
                1. To iterate over an `tools` list, do the following:

                .. code-block:: python
                
                from pyattck import Attck

                attck = Attck()

                for tool in attck.enterprise.tools:
                    print(tool.id)
                    print(tool.name)
                    print(tool.description)
                    # etc.

                2. To access relationship properties, do the following:

                .. code-block:: python

                from pyattck import Attck

                attck = Attck()

                for tool in attck.enterprise.tools:
                    print(tool.id)
                    print(tool.name)
                    print(tool.description)
                    # etc.

                    for technique in tool.techniques:
                        print(technique.name)
                        print(technique.description)
                        # etc.

        Arguments:
            attck_obj (json) -- Takes the raw MITRE ATT&CK Json object
            AttckObject (dict) -- Takes the MITRE ATT&CK Json object as a kwargs values
    '''

    __ATTCK_C2_DATASETS = None
    __ATTCK_TOOLS_DATASETS = None

    def __init__(self, attck_obj = None, **kwargs):
        """This class represents a Tool as defined with the Enterprise MITRE ATT&CK framework.

        Keyword Arguments:
            attck_obj {json} -- A Enterprise MITRE ATT&CK Framework json object (default: {None})

        Raises:
            GeneratedDatasetException: Raised an exception when unable to access or process the external generated dataset.
        """
        super(AttckTools, self).__init__(**kwargs)
        self.__attck_obj = attck_obj

        self.id = self._set_id(kwargs)
        self.name = self._set_attribute(kwargs, 'name')
        self.description = self._set_attribute(kwargs, 'description')
        self.reference = self._set_reference(kwargs)
        self.created = self._set_attribute(kwargs, 'created')
        self.modified = self._set_attribute(kwargs, 'modified')
        self.stix = self._set_attribute(kwargs, 'id')
        self.type = self._set_attribute(kwargs, 'type')
        self.wiki = self._set_wiki(kwargs)
        self.contributor = self._set_attribute(kwargs, 'contributor')

        self.set_relationships(self.__attck_obj)

        if AttckTools.__ATTCK_C2_DATASETS is None or AttckTools.__ATTCK_TOOLS_DATASETS is None:
            try:
                data = AttckDatasets().generated_attck_data()
            except:
                raise GeneratedDatasetException('Unable to retrieve generated attack data properties')
            if AttckTools.__ATTCK_C2_DATASETS is None:
                if 'c2_data' in data:
                    AttckTools.__ATTCK_C2_DATASETS = data['c2_data']
            if AttckTools.__ATTCK_TOOLS_DATASETS is None:
                if 'tools' in data:
                    AttckTools.__ATTCK_TOOLS_DATASETS = data['tools']

        self.c2_data = self.__get_c2_dataset()
        self.external_dataset =  self.__get_tools_dataset()



    def __get_tools_dataset(self):
        return_list = []
        self.additional_names = []
        self.attribution_links = []
        self.additional_comments = []
        self.family = []
        for tool in AttckTools.__ATTCK_TOOLS_DATASETS['tools']:
            if 'names' in tool:
                if tool['names']:
                    if self.name.lower() in [x.lower() for x in tool['names']]:
                        return_list.append(tool)
                        for name in tool['names']:
                            self.additional_names.append(name)
                        if 'links' in tool:
                            for link in tool['links']:
                                self.attribution_links.append(link)
                        if 'family' in tool:
                            for family in tool['family']:
                                self.family.append(family)
                        if 'comments' in tool:
                            self.family.append(tool['comments'])
                    if self.alias:
                        for alias in self.alias:
                            if alias.lower() in [x.lower() for x in tool['names']]:
                                return_list.append(tool)
                                for name in tool['names']:
                                    self.additional_names.append(name)
                                if 'links' in tool:
                                    for link in tool['links']:
                                        self.attribution_links.append(link)
                                if 'family' in tool:
                                    for family in tool['family']:
                                        self.family.append(family)
                                if 'comments' in tool:
                                    self.family.append(tool['family'])
        if return_list:
            return return_list
        else:
            return None

    def __get_c2_dataset(self):
        return_dict = {}
        for k,v in AttckTools.__ATTCK_C2_DATASETS.items():
            if self.name.lower() == k.lower():
                return_dict[k] = v
                for key,val in v.items():
                    try:
                        setattr(self, key, val)
                    except:
                        setattr(self, 'c2_{}'.format(key), val)
            if self.alias:
                for item in self.alias:
                    if item.lower() == k.lower():
                        return_dict[k] = v
                        for key,val in v.items():
                            try:
                                setattr(self, key, val)
                            except:
                                setattr(self, 'c2_{}_{}'.format(item.lower(), key), val)
        if return_dict:
            return return_dict
        else:
            return None

    @property
    def techniques(self):
        """Returns all technique objects that a tool object is associated with

        Returns:
            [list] -- A list of technique objects defined within the Enterprise MITRE ATT&CK Framework
        """
        from .technique import AttckTechnique
        return_list = []
        item_dict = {}
        for item in self.__attck_obj['objects']:
            if 'type' in item:
                if item['type'] == 'attack-pattern':
                    item_dict[item['id']] = item
        
        for item in self._RELATIONSHIPS[self.stix]:
            if item in item_dict:
                return_list.append(AttckTechnique(**item_dict[item]))
        return return_list

    @property
    def actors(self):
        """Returns all actor objects that use a tool

        Returns:
            [list] -- A list of actor objects defined within the Enterprise MITRE ATT&CK Framework
        """
        from .actor import AttckActor
        return_list = []
        item_dict = {}
        for item in self.__attck_obj['objects']:
            if 'type' in item:
                if item['type'] == 'intrusion-set':
                    item_dict[item['id']] = item
        
        for item in self._RELATIONSHIPS[self.stix]:
            if item in item_dict:
                return_list.append(AttckActor(**item_dict[item]))
        return return_list