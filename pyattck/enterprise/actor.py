from .attckobject import AttckObject


class AttckActor(AttckObject):

    """Enterprise MITRE ATT&CK Actor object

    A child class of AttckObject

    Creates objects that are categorized as Mitre ATT&CK Enterprise
    Actors or Groups (e.g. APT1, APT32, etc.)

    You can also access external data properties. The following properties
    are generated using external data:

        1. country
        2. operations
        3. attribution_links
        4. known_tools
        5. targets
        6. additional_comments
        7. external_description

    You can retrieve the entire dataset using the `external_dataset` property.

    Example:
        You can iterate over an `actors` list and access specific properties and
        relationship properties.

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
                   print(actor.alias)
                   print(actor.description)
                   # etc.

            2. To access relationship properties, do the following:

            .. code-block:: python

               from pyattck import Attck

               attck = Attck()

               for actor in attck.enterprise.actors:
                   print(actor.id)
                   print(actor.name)
                   print(actor.alias)
                   print(actor.description)

                   for malware in actor.malwares:
                       print(malware.name)
                       print(malware.description)
                       # etc.

    Arguments:
        attck_obj (json) -- Takes the raw Mitre ATT&CK Json object
        AttckObject (dict) -- Takes the Mitre ATT&CK Json object as a
                              kwargs values
    """

    __ATTCK_DATASETS = None

    def __init__(self, attck_obj = None, **kwargs):
        """
        This class represents a Actor (or group) as defined by the
        Enterprise MITRE ATT&CK framework.

        Keyword Arguments:
            attck_obj {json} -- A Enterprise MITRE ATT&CK Framework
                                json object (default: {None})

        Raises:
            GeneratedDatasetException: Raised an exception when unable
                                       to access or process the external
                                       generated dataset.
        """
        super(AttckActor, self).__init__(**kwargs)
        self.__attck_obj = attck_obj
        self.id = self._set_id(kwargs)
        self.created_by_ref = self._set_attribute(kwargs, 'created_by_ref')
        self.revoked = self._set_attribute(kwargs, 'revoked')
        self.name = self._set_attribute(kwargs, 'name')
        self.description = self._set_attribute(kwargs, 'description')
        self.external_reference = self._set_reference(kwargs)
        self.created = self._set_attribute(kwargs, 'created')
        self.modified = self._set_attribute(kwargs, 'modified')
        self.stix = self._set_attribute(kwargs, 'id')
        self.type = self._set_attribute(kwargs, 'type')
        self.wiki = self._set_wiki(kwargs)
        self.contributor = self._set_list_items(kwargs, 'x_mitre_contributors')
        self.set_relationships(self.__attck_obj)
        self.external_dataset = self.__get_actors_dataset()

    def __get_actors_dataset(self):
        return_list = []
        countries = set()
        operations = set()
        attribution_links = set()
        known_tools = set()
        targets = set()
        additional_comments = set()
        external_description = set()
        for country in AttckObject.generated_attck_json.get('actors'):
            if country:
                for key,val in country.items():
                    for actor in val.get('actors'):
                        if self.name in actor.get('names') or hasattr(self, 'alias') and self.alias and any(x in actor.get('names') for x in self.alias):
                            countries.add(key)
                            if actor.get('operations'):
                                operations.update(actor.get('operations'))
                            if actor.get('links'):
                                attribution_links.update(actor.get('links'))
                            if actor.get('tools'):
                                known_tools.update(actor.get('tools'))
                            if actor.get('targets'):
                                targets.add(actor.get('targets'))
                            if actor.get('comment'):
                                additional_comments.update(actor.get('comment',[]))
                            if actor.get('description'):
                                external_description.update(actor.get('description'))
                            return_list.append(actor)
        self.country = list(countries)
        self.operations = list(operations)
        self.attribution_links = list(attribution_links)
        self.known_tools = list(known_tools)
        self.targets = list(targets)
        self.additional_comments = list(additional_comments)
        self.external_description = list(external_description)
        return return_list

    @property
    def malwares(self):
        """
        Returns all malware objects as a list that are documented as being
        used by an Actor or Group

        Returns:
            [list] -- A list of related malware objects defined within the
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
            for item in self._RELATIONSHIPS[self.stix]:
                if item in item_dict:
                    return_list.append(AttckMalware(attck_obj=self.__attck_obj, **item_dict[item]))
        return return_list

    @property
    def tools(self):
        """
        Returns all tool object as a list that are documented as being
        used by an Actor or Group

        Returns:
            [list] -- A list of related tool objects defined within the
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
    def techniques(self):
        """
        Returns all technique objects as a list that are documented as
        being used by an Actor or Group

        Returns:
            [list] -- A list of related technique objects defined within the
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
