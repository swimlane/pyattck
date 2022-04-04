from .attckobject import AttckObject


class AttckTactic(AttckObject):
    """ICS MITRE ATT&CK Tactic object.

    A child class of AttckObject

    Creates objects that are categorized as Mitre ATT&CK Tactics

    Example:

        You can iterate over an `tactics` list and access specific
        properties and relationship properties.

        The following relationship properties are accessible:
                1. techniques

        1. To iterate over an `tactics` list, do the following:

        .. code-block:: python

            from pyattck import Attck

            attck = Attck()

            for tactic in attck.ics.tactics:
                print(tactic.id)
                print(tactic.name)
                print(tactic.alias)
                print(tactic.description)
                # etc.

        2. To access relationship properties, do the following:

        .. code-block:: python

            from pyattck import Attck

            attck = Attck()

            for tactic in attck.ics.tactics:
                print(tactic.id)
                print(tactic.name)
                print(tactic.alias)
                print(tactic.description)
                # etc.

                for technique in tactic.techniques:
                    print(technique.name)
                    print(technique.description)
                    # etc.

    Arguments:
        attck_obj (json) -- Takes the raw Mitre ATT&CK Json object
        AttckObject (dict) -- Takes the Mitre ATT&CK Json object as a kwargs values
    """

    def __init__(self, attck_obj=None, _enterprise_attck_obj=None, **kwargs):
        """
        This class represents a Tactic as defined by the
        ICS MITRE ATT&CK framework.

        Keyword Arguments:
            attck_obj {json} -- A ICS MITRE ATT&CK Framework
                                json object (default: {None})
        """
        super(AttckTactic, self).__init__(**kwargs)
        self.__attck_obj = attck_obj
        self.__enterprise_attck_obj = _enterprise_attck_obj
        self.id = self._set_id(kwargs)
        self.created_by_ref = self._set_attribute(kwargs, 'created_by_ref')
        self.type = self._set_attribute(kwargs, 'type')
        self.name = self._set_attribute(kwargs, 'name')
        self.description = self._set_attribute(kwargs, 'description')
        self.external_reference = self._set_reference(kwargs)
        self.created = self._set_attribute(kwargs, 'created')
        self.modified = self._set_attribute(kwargs, 'modified')
        self.stix = self._set_attribute(kwargs, 'id')
        self.short_name = self._set_attribute(kwargs, 'x_mitre_shortname')
        self.wiki = self._set_wiki(kwargs)
        self.contributor = self._set_attribute(kwargs, 'contributor')
        self.set_relationships(self.__attck_obj)

    @property
    def techniques(self):
        """
        Returns all technique objects as a list that are
        associated with a Tactic

        Returns:
            [list] -- A list of related technique objects defined
                      within the ICS MITRE ATT&CK Framework
        """
        from .technique import AttckTechnique
        technique_list = []
        for item in self.__attck_obj['objects']:
            if 'kill_chain_phases' in item:
                for prop in item['kill_chain_phases']:
                    if str(prop['phase_name']).lower() == str(self.short_name).lower():
                        technique_list.append(AttckTechnique(attck_obj=self.__attck_obj,
                                                             _enterprise_attck_obj=self.__enterprise_attck_obj, **item))
        return technique_list
