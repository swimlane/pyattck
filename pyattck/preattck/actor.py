from .preattckobject import PreAttckObject


class PreAttckActor(PreAttckObject):

    """MITRE PRE-ATT&CK Actor object.

    A child class of PreAttckObject

    Creates objects that are categorized as MITRE PRE-ATT&CK Actors or
    Groups (e.g. APT1, APT32, etc.)

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
    """

    def __init__(self, preattck_obj = None, **kwargs):
        """
        Creates objects that are categorized as
        MITRE PRE-ATT&CK Actors or Groups (e.g. APT1, APT32, etc.)

        Arguments:
            attck_obj (json) -- Takes the raw MITRE PRE-ATT&CK Json object
            AttckObject (dict) -- Takes the MITRE PRE-ATT&CK Json object as
                                  a kwargs values

        Raises:
            GeneratedDatasetException: Error when accessing third-party
                                       generated datasets
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
        for country in PreAttckObject.generated_attck_json.get('actors'):
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
    def techniques(self):
        """
        Accessing an actors known techniques as part of the
        MITRE PRE-ATT&CK Framework

        Returns:
            list: Returns all technique objects as a list that
                  are documented as being used by an Actor or Group
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
                return_list.append(PreAttckTechnique(preattck_obj=self.__preattck_obj, **item_dict[item]))
        return return_list
