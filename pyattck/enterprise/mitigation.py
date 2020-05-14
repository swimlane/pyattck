from .attckobject import AttckObject


class AttckMitigation(AttckObject):
    '''A child class of AttckObject

       Creates objects which have been categorized as potential mitigations
    
    Example:
        You can iterate over a `mitigations` list and access specific properties and relationship properties.

        The following relationship properties are accessible:
                1. techniques
        
            1. To iterate over an `mitigations` list, do the following:

            .. code-block:: python
               
               from pyattck import Attck

               attck = Attck()

               for mitigation in attck.enterprise.mitigations:
                   print(mitigation.id)
                   print(mitigation.name)
                   print(mitigation.description)
                   # etc.

            2. To access relationship properties, do the following:

            .. code-block:: python

               from pyattck import Attck

               attck = Attck()

               for mitigation in attck.enterprise.mitigations:
                   print(mitigation.id)
                   print(mitigation.name)
                   print(mitigation.description)
                   # etc.

                   for technique in mitigation.techniques:
                       print(technique.name)
                       print(technique.description)
                       # etc.

    Arguments:s
        attck_obj (json) -- Takes the raw Mitre ATT&CK Json object
        AttckObject (dict) -- Takes the Mitre ATT&CK Json object as a kwargs values
    '''

    def __init__(self, attck_obj = None, **kwargs):
        """This class represents mitigation guidance as defined with the Enterprise MITRE ATT&CK framework.

        Keyword Arguments:
            attck_obj {json} -- A Enterprise MITRE ATT&CK Framework json object (default: {None})
        """
        super(AttckMitigation, self).__init__(**kwargs)
        self.__attck_obj = attck_obj
        
        self.created_by_ref = self._set_attribute(kwargs, 'created_by_ref')
        self.id = self._set_id(kwargs)
        self.name = self._set_attribute(kwargs, 'name')
        self.description = self._set_attribute(kwargs, 'description')
        self.external_reference = self._set_reference(kwargs)
        self.created = self._set_attribute(kwargs, 'created')
        self.modified = self._set_attribute(kwargs, 'modified')
        self.stix = self._set_attribute(kwargs, 'id')
        self.type = self._set_attribute(kwargs, 'type')
        self.wiki = self._set_wiki(kwargs)
        self.contributor = self._set_attribute(kwargs, 'contributor')

        self.set_relationships(self.__attck_obj)

    @property
    def techniques(self):
        """Returns all technique objects as a list that are associated with this mitigation advice from the Enterprise MITRE ATT&CK Framework

        Returns:
            [list] -- A list of related technique objects defined within the Enterprise MITRE ATT&CK Framework for a mitigation object
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