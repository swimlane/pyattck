from attckobject import AttckObject

class AttckTechnique(AttckObject):
    """A child class of AttckObject
       Creates objects which have been categorized as a technique used by attackers
    
    Arguments:
        AttckObject (dict) -- Takes the Mitre ATT&CK Json object as a kwargs values
    """

    def __init__(self, tactic_list = None, **kwargs):
        """Creates an AttckTechnique object.  
           The AttckTechnique object is a technique used by attackers.
        """

        self.id = super(AttckTechnique, self)._set_id(kwargs)
        self.name = super(AttckTechnique, self)._set_attribute(kwargs, 'name')
        self.alias = super(AttckTechnique, self)._set_attribute(kwargs, 'aliases')
        self.description = super(AttckTechnique, self)._set_attribute(kwargs, 'description')
        self.type = super(AttckTechnique, self)._set_attribute(kwargs, 'type')
        self.wiki = super(AttckTechnique, self)._set_wiki(kwargs)
        self.platform = super(AttckTechnique, self)._set_attribute(kwargs, 'x_mitre_platforms')
        self.permission = super(AttckTechnique, self)._set_attribute(kwargs, 'x_mitre_permissions_required')
        self.bypass = super(AttckTechnique, self)._set_attribute(kwargs, 'x_mitre_defense_bypassed')
        self.effective_permissions = super(AttckTechnique, self)._set_attribute(kwargs, 'x_mitre_effective_permissions')
        self.network = super(AttckTechnique, self)._set_attribute(kwargs, 'x_mitre_network_requirements')
        self.remote = super(AttckTechnique, self)._set_attribute(kwargs, 'x_mitre_remote_support')
        self.system_requirements = super(AttckTechnique, self)._set_attribute(kwargs, 'x_mitre_system_requirements')
        self.detection = super(AttckTechnique, self)._set_attribute(kwargs, 'x_mitre_detection')
        self.data_source = super(AttckTechnique, self)._set_attribute(kwargs, 'x_mitre_data_sources')
        self.created = super(AttckTechnique, self)._set_attribute(kwargs, 'created')
        self.modified = super(AttckTechnique, self)._set_attribute(kwargs, 'modified')
        self.contributor = super(AttckTechnique, self)._set_attribute(kwargs, 'contributor')
        self.stix = super(AttckTechnique, self)._set_attribute(kwargs, 'id')

        self.wiki = super(AttckTechnique, self)._set_wiki(kwargs)
        self.reference = super(AttckTechnique, self)._set_reference(kwargs)

        self.tactic = self._set_tactic(kwargs)
        self.mitigation = self._set_mitigation(tactic_list, kwargs)
        

    def _set_tactic(self, obj):
        """Sets the associated tactic/phase this technique is in
        
        Arguments:
            obj (dict) -- A Mitre ATT&CK Framework json object
        
        Returns:
            (string) -- Returns a string that sets the tactic/phase this technique is in. 
                        If there is no phase found, it will return 'no phase_name'
        """

        temp_list = []
        try:
            for phase in obj['kill_chain_phases']:
                temp_list = phase['phase_name']
            return temp_list
        except:
            return 'no phase_name'
    

    def _set_mitigation(self, tactic_list, obj):
        """Returns the mitigation guidance for this technique based on the provided tactic list
        
        Arguments:
            tactic_list (dict) -- A Mitre ATT&CK Framework json object that has been pre-filtered to just include tactics
            obj (dict)-- A Mitre ATT&CK Framework json object
        
        Returns:
            (str) -- Returns the tactics description which includes mitigation steps.  
                     If no description is found it will return 'no mitigation guidance provided'
        """

        if 'name' in obj:
            for tactic in tactic_list:
                if obj['name'] == tactic.name:
                    if tactic.description:
                        return tactic.description
                    else:
                        return 'no mitigation guidance provided'
        