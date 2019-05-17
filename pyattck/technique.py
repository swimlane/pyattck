from .attckobject import AttckObject

class AttckTechnique(AttckObject):
    """A child class of AttckObject
       Creates objects which have been categorized as a technique used by attackers
    
    Arguments:
        AttckObject (dict) -- Takes the Mitre ATT&CK Json object as a kwargs values
    """

    def __init__(self, attck_obj = None, **kwargs):
        """Creates an AttckTechnique object.  
           The AttckTechnique object is a technique used by attackers.
        """

        self.attck_obj = attck_obj

        self.created_by_reference = super(AttckTechnique, self)._set_attribute(kwargs, 'created_by_ref')
        self.id = super(AttckTechnique, self)._set_id(kwargs)
        self.name = super(AttckTechnique, self)._set_attribute(kwargs, 'name')
        self.alias = super(AttckTechnique, self)._set_attribute(kwargs, 'aliases')
        self.description = super(AttckTechnique, self)._set_attribute(kwargs, 'description')
        self.type = super(AttckTechnique, self)._set_attribute(kwargs, 'type')
        self.wiki = super(AttckTechnique, self)._set_wiki(kwargs)
        self.platforms = super(AttckTechnique, self)._set_list_items(kwargs, 'x_mitre_platforms')
        self.permissions = super(AttckTechnique, self)._set_list_items(kwargs, 'x_mitre_permissions_required')
        self.bypass = super(AttckTechnique, self)._set_list_items(kwargs, 'x_mitre_defense_bypassed')
        self.effective_permissions = super(AttckTechnique, self)._set_list_items(kwargs, 'x_mitre_effective_permissions')
        self.network = super(AttckTechnique, self)._set_attribute(kwargs, 'x_mitre_network_requirements')
        self.remote = super(AttckTechnique, self)._set_attribute(kwargs, 'x_mitre_remote_support')
        self.system_requirements = super(AttckTechnique, self)._set_attribute(kwargs, 'x_mitre_system_requirements')
        self.detection = super(AttckTechnique, self)._set_attribute(kwargs, 'x_mitre_detection')
        self.data_source = super(AttckTechnique, self)._set_list_items(kwargs, 'x_mitre_data_sources')
        self.created = super(AttckTechnique, self)._set_attribute(kwargs, 'created')
        self.modified = super(AttckTechnique, self)._set_attribute(kwargs, 'modified')
        self.contributors = super(AttckTechnique, self)._set_list_items(kwargs, 'contributor')
        self.stix = super(AttckTechnique, self)._set_attribute(kwargs, 'id')

        self.wiki = super(AttckTechnique, self)._set_wiki(kwargs)
        self.external_references = super(AttckTechnique, self)._set_reference(kwargs)

        self.tactic = kwargs

    @property
    def tactic(self):
        '''Returns all tactics as a list that this technique is found in'''
        from tactic import AttckTactic
        tactic_list = []
        for item in self.attck_obj['objects']:
            if 'x-mitre-tactic' in item['type']:
                if str(self._tactic).lower() == str(item['x_mitre_shortname']).lower():
                    tactic_list.append(AttckTactic(**item))
        return tactic_list
            

    @tactic.setter
    def tactic(self, obj):
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
            self._tactic = temp_list
        except:
            self._tactic = 'no phase_name'
        

    @property
    def mitigation(self):
        '''Returns all mitigation objects as a list that are documented to help mitigate the current technique object'''
        from mitigation import AttckMitigation
        mitigation_list = []
        for item in self.attck_obj['objects']:
            if 'relationship_type' in item:
                if 'mitigates' in item['relationship_type']:
                    if self.stix in item['target_ref']:
                        for o in self.attck_obj['objects']:
                            if item['source_ref'] in o['id']:
                                mitigation_list.append(AttckMitigation(**o))
        return mitigation_list        


    @property
    def actors(self):
        '''Returns all actor objects that have been identified as using this technique'''
        from actor import AttckActor
        actor_list = []
        for item in self.attck_obj['objects']:
            if 'relationship_type' in item:
                if 'uses' in item['relationship_type']:
                    if self.stix in item['target_ref']:
                        if 'intrusion-set' in item['source_ref']:
                            for o in self.attck_obj['objects']:
                                if item['source_ref'] in o['id']:
                                    actor_list.append(AttckActor(**o))
        return actor_list