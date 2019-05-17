from .attckobject import AttckObject

class AttckTactic(AttckObject):
    
    def __init__(self, attck_obj = None, **kwargs):
        '''The AttckTactic class is used to gather information about all Mitre ATT&CK Framework Tactics.
        To access this class directly you must first instantiate it and provide the appropriate inputs, but it is easier to use the Attck class wrapper.

        Args:
            attck_obj ([json]): This should be the raw Mitre ATT&CK json object. Defaults to None, but should be provided

        '''

        self.attck_obj = attck_obj

        self.id = super(AttckTactic, self)._set_id(kwargs)
        self.created_by_ref = super(AttckTactic, self)._set_attribute(kwargs, 'created_by_ref')
        self.type = super(AttckTactic, self)._set_attribute(kwargs, 'type')
        self.name = super(AttckTactic, self)._set_attribute(kwargs, 'name')
        self.description = super(AttckTactic, self)._set_attribute(kwargs, 'description')
        self.external_reference = super(AttckTactic, self)._set_reference(kwargs)
        self.created = super(AttckTactic, self)._set_attribute(kwargs, 'created')
        self.modified = super(AttckTactic, self)._set_attribute(kwargs, 'modified')
        self.stix = super(AttckTactic, self)._set_attribute(kwargs, 'id')
        self.short_name = super(AttckTactic, self)._set_attribute(kwargs, 'x_mitre_shortname')
        self.wiki = super(AttckTactic, self)._set_wiki(kwargs)

    @property
    def techniques(self):
        '''Returns all techniques as a list that are related to this tactic'''
        from technique import AttckTechnique
        technique_list = []
        for item in self.attck_obj['objects']:
            if 'kill_chain_phases' in item:
                for prop in item['kill_chain_phases']:
                    if str(prop['phase_name']).lower() == str(self.name).lower():
                        technique_list.append(AttckTechnique(**item))
        return technique_list