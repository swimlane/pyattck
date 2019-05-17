from .attckobject import AttckObject

class AttckMitigation(AttckObject):
    """A child class of AttckObject
       Creates objects which have been categorized as potential mitigations
    
    Arguments:
        AttckObject (dict) -- Takes the Mitre ATT&CK Json object as a kwargs values
    """

    def __init__(self, attck_obj = None, **kwargs):
        """Creates an AttckTactic object.  
           The AttckMitigation object is considered a list of mitigations to threats based on the Mitre ATT&CK Framework
        """

        self.attck_obj = attck_obj
        
        self.created_by_ref = super(AttckMitigation, self)._set_attribute(kwargs, 'created_by_ref')
        self.id = super(AttckMitigation, self)._set_id(kwargs)
        self.name = super(AttckMitigation, self)._set_attribute(kwargs, 'name')
        self.description = super(AttckMitigation, self)._set_attribute(kwargs, 'description')
        self.external_reference = super(AttckMitigation, self)._set_reference(kwargs)
        self.created = super(AttckMitigation, self)._set_attribute(kwargs, 'created')
        self.modified = super(AttckMitigation, self)._set_attribute(kwargs, 'modified')
        self.stix = super(AttckMitigation, self)._set_attribute(kwargs, 'id')
        self.type = super(AttckMitigation, self)._set_attribute(kwargs, 'type')
        self.wiki = super(AttckMitigation, self)._set_wiki(kwargs)

    @property
    def techniques(self):
        '''Returns all technique objects as a list that are related to this mitigation object'''
        from technique import AttckTechnique
        technique_list = []
        for item in self.attck_obj['objects']:
            if 'source_ref' in item:
                if self.stix in item['source_ref']:
                    for o in self.attck_obj['objects']:
                        if item['target_ref'] in o['id']:
                            technique_list.append(AttckTechnique(**o))
        return technique_list