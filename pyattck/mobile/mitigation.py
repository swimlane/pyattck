from .mobileattckobject import MobileAttckObject


class MobileAttckMitigation(MobileAttckObject):

    """Mobile MITRE ATT&CK Mitigation object.

    A child class of MobileAttckObject

    Creates objects which have been categorized as potential mitigations

    Example:
        You can iterate over a `mitigations` list and access specific properties
        and relationship properties.

        The following relationship properties are accessible:
                1. techniques

            1. To iterate over an `mitigations` list, do the following:

            .. code-block:: python

               from pyattck import Attck

               attck = Attck()

               for mitigation in attck.mobile.mitigations:
                   print(mitigation.id)
                   print(mitigation.name)
                   print(mitigation.description)
                   # etc.

            2. To access relationship properties, do the following:

            .. code-block:: python

               from pyattck import Attck

               attck = Attck()

               for mitigation in attck.mobile.mitigations:
                   print(mitigation.id)
                   print(mitigation.name)
                   print(mitigation.description)
                   # etc.

                   for technique in mitigation.techniques:
                       print(technique.name)
                       print(technique.description)
                       # etc.
    """

    def __init__(self, mobile_attck_obj = None, **kwargs):
        """
        Creates an MobileAttckMitigation object.  
        The MobileAttckMitigation object is considered a list of mitigations to
        threats based on the MITRE Mobile ATT&CK Framework

        Arguments:
            mobile_attck_obj (json) -- Takes the raw MITRE Mobile ATT&CK Json object
            AttckObject (dict) -- Takes the MITRE Mobile ATT&CK Json object as a kwargs values
        """
        super(MobileAttckMitigation, self).__init__(**kwargs)
        self.__mobile_attck_obj = mobile_attck_obj
        self.old_attack_id = self._set_attribute(kwargs, 'x_mitre_old_attack_id')
        self.external_reference = self._set_reference(kwargs)
        self.created_by_ref = self._set_attribute(kwargs, 'created_by_ref')
        self.version = self._set_attribute(kwargs, 'x_mitre_version')
        self.stix = self._set_attribute(kwargs, 'id')
        self.wiki = self._set_wiki(kwargs)
        self.set_relationships(self.__mobile_attck_obj)

    @property
    def techniques(self):
        """
        Accessing known techniques that this mitigation advice is associated
        with as part of the MITRE Mobile ATT&CK Framework

        Returns:
            list: Returns all technique objects as a list that are associated with
                  a mitigation object
        """
        from .technique import MobileAttckTechnique
        return_list = []
        item_dict = {}
        for item in self.__mobile_attck_obj['objects']:
            if 'type' in item:
                if item['type'] == 'attack-pattern':
                    item_dict[item['id']] = item
        for item in self._RELATIONSHIPS[self.stix]:
            if item in item_dict:
                return_list.append(MobileAttckTechnique(mobile_attck_obj=self.__mobile_attck_obj, **item_dict[item]))
        return return_list
