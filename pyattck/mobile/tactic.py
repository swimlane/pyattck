from .mobileattckobject import MobileAttckObject


class MobileAttckTactic(MobileAttckObject):
    
    '''A child class of MobileAttckObject
    
        Creates objects that are categorized as MITRE Mobile ATT&CK Tactics
    
        Example:
        
            You can iterate over an `tactics` list and access specific properties and relationship properties.

            The following relationship properties are accessible:
                    1. techniques
        
            1. To iterate over an `tactics` list, do the following:

            .. code-block:: python
               
               from pyattck import Attck

               attck = Attck()

               for tactic in attck.mobile.tactics:
                   print(tactic.id)
                   print(tactic.name)
                   print(tactic.alias)
                   print(tactic.description)
                   # etc.

            2. To access relationship properties, do the following:

            .. code-block:: python

               from pyattck import Attck

               attck = Attck()

               for tactic in attck.mobile.tactics:
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
            mobile_attck_obj (json) -- Takes the raw MITRE Mobile ATT&CK Json object
            AttckObject (dict) -- Takes the MITRE Mobile ATT&CK Json object as a kwargs values
        '''

    def __init__(self, mobile_attck_obj = None, **kwargs):
        """This class represents a Tactic as defined with the Mobile MITRE ATT&CK framework.

        Keyword Arguments:
            mobile_attck_obj {json} -- A Mobile MITRE ATT&CK Framework json object (default: {None})
        """
        super(MobileAttckTactic, self).__init__(**kwargs)
        self.__mobile_attck_obj = mobile_attck_obj
   
        self.created_by_ref = self._set_attribute(kwargs, 'created_by_ref')
        self.short_name = self._set_attribute(kwargs, 'x_mitre_shortname')
        self.external_reference = self._set_reference(kwargs)
        self.stix = self._set_attribute(kwargs, 'id')
        self.wiki = self._set_wiki(kwargs)
        
        self.set_relationships(self.__mobile_attck_obj)

    @property
    def techniques(self):
        """Accessing techniques that belong to a tactic as part of the MITRE Mobile ATT&CK Framework

        Returns:
            list: Returns all technique objects as a list that are associated with a tactic object
        """
        from .technique import MobileAttckTechnique
        technique_list = []
        for item in self.__mobile_attck_obj['objects']:
            if 'kill_chain_phases' in item:
                for prop in item['kill_chain_phases']:
                    if str(prop['phase_name']).lower() == str(self.short_name).lower():
                        technique_list.append(MobileAttckTechnique(**item))
        return technique_list