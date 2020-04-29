from .preattckobject import PreAttckObject

class PreAttckTactic(PreAttckObject):
    
    def __init__(self, preattck_obj = None, **kwargs):
        '''A child class of PreAttckObject
    
        Creates objects that are categorized as MITRE PRE-ATT&CK Tactics
    
        Example:
        
            You can iterate over an `tactics` list and access specific properties and relationship properties.

            The following relationship properties are accessible:
                    1. techniques
        
            1. To iterate over an `tactics` list, do the following:

            .. code-block:: python
               
               from pyattck import Attck

               attck = Attck()

               for tactic in attck.preattack.tactics:
                   print(tactic.id)
                   print(tactic.name)
                   print(tactic.aliases)
                   print(tactic.description)
                   # etc.

            2. To access relationship properties, do the following:

            .. code-block:: python

               from pyattck import Attck

               attck = Attck()

               for tactic in attck.preattack.tactics:
                   print(tactic.id)
                   print(tactic.name)
                   print(tactic.aliases)
                   print(tactic.description)
                   # etc.

                   for technique in tactic.techniques:
                       print(technique.name)
                       print(technique.description)
                       # etc.

        Arguments:
            attck_obj (json) -- Takes the raw MITRE PRE-ATT&CK Json object
            AttckObject (dict) -- Takes the MITRE PRE-ATT&CK Json object as a kwargs values
        '''
        super(PreAttckTactic, self).__init__(**kwargs)
        self.preattck_obj = preattck_obj

        self.created_by_ref = self._set_attribute(kwargs, 'created_by_ref')
        self.stix = self._set_attribute(kwargs, 'id')
        self.short_name = self._set_attribute(kwargs, 'x_mitre_shortname')
        

        self.set_relationships(self.preattck_obj)

    @property
    def techniques(self):
        """Accessing techniques a specific tactic belongs to based on the MITRE PRE-ATT&CK Framework

        Returns:
            list: Returns all technique objects within the defined tactic
        """
        from .technique import PreAttckTechnique
        technique_list = []
        for item in self.preattck_obj['objects']:
            if 'kill_chain_phases' in item:
                for prop in item['kill_chain_phases']:
                    if str(prop['phase_name']).lower() == str(self.short_name).lower():
                        technique_list.append(PreAttckTechnique(**item))
        return technique_list