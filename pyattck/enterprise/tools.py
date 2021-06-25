from .attckobject import AttckObject


class AttckTools(AttckObject):

    """Enterprise MITRE ATT&CK Tool object.

    A child class of AttckObject

    Creates objects which have been categorized as tools or software which have
    been categorized as software used in attacks

    You can also access external data properties. The following properties are
    generated using external data:

        1. additional_names
        2. attribution_links
        3. additional_comments
        4. family

    You can retrieve the entire dataset using the `external_dataset` property.

    You can also access external data properties from the C2 Matrix project.
    The following properties are generated using C2 Matrix external data:

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
        You can iterate over an `tools` list and access specific properties
        and relationship properties.

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
    """

    def __init__(self, attck_obj = None, **kwargs):
        """
        This class represents a Tool as defined by the
        Enterprise MITRE ATT&CK framework.

        Keyword Arguments:
            attck_obj {json} -- A Enterprise MITRE ATT&CK Framework
                                json object (default: {None})

        Raises:
            GeneratedDatasetException: Raised an exception when unable to access
                                       or process the external generated dataset.
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
        self.c2_data = self.__get_c2_dataset()
        self.external_dataset =  self.__get_tools_dataset()

    def __get_tools_dataset(self):
        return_list = []
        self.additional_names = set()
        self.attribution_links = set()
        self.additional_comments = set()
        self.family = set()
        for tool in AttckObject.generated_attck_json['tools'].get('tools'):
            if tool.get('names'):
                if self.name.lower() in [x.lower() for x in tool.get('names')] or hasattr(self, 'alias') and any(x.lower() in tool.get('names') for x in self.alias):
                    self.additional_names.update(tool.get('names'))
                    if tool.get('links'):
                        self.attribution_links.update(tool['links'])
                    if tool.get('family'):
                        self.family.update(tool['family'])
                    if tool.get('comments'):
                        self.additional_comments.update(tool['comments'])
                    return_list.append(tool)
        self.additional_names = list(self.additional_names)
        self.attribution_links = list(self.attribution_links)
        self.additional_comments = list(self.additional_comments)
        self.family = list(self.family)
        return return_list

    def __get_c2_dataset(self):
        return_dict = {}
        for k,v in AttckObject.generated_attck_json['c2_data'].items():
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
        return return_dict if return_dict else None

    @property
    def techniques(self):
        """
        Returns all technique objects that a tool object is associated with

        Returns:
            [list] -- A list of technique objects defined within the
                      Enterprise MITRE ATT&CK Framework
        """
        from .technique import AttckTechnique
        return_list = []
        item_dict = {}
        for item in self.__attck_obj['objects']:
            if 'type' in item:
                if item['type'] == 'attack-pattern':
                    item_dict[item['id']] = item
        if self._RELATIONSHIPS.get(self.stix):
            for item in self._RELATIONSHIPS[self.stix]:
                if item in item_dict:
                    return_list.append(AttckTechnique(attck_obj=self.__attck_obj, **item_dict[item]))
        return return_list

    @property
    def actors(self):
        """
        Returns all actor objects that use a tool

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
