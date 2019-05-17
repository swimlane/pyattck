from .attckobject import AttckObject

class AttckTools(AttckObject):
    """A child class of AttckObject
       Creates objects which have been categorized as software used in attacks
    
    Arguments:
        AttckObject (dict) -- Takes the Mitre ATT&CK Json object as a kwargs values
    """

    def __init__(self, attck_obj = None, **kwargs):
        """Creates an AttckTools object.  
           The AttckTools object is based on software which have been categorized as software used in attacks
        """

        self.attck_obj = attck_obj

        self.id = super(AttckTools, self)._set_id(kwargs)
        self.name = super(AttckTools, self)._set_attribute(kwargs, 'name')
        self.alias = super(AttckTools, self)._set_attribute(kwargs, 'aliases')
        self.description = super(AttckTools, self)._set_attribute(kwargs, 'description')
        self.reference = super(AttckTools, self)._set_reference(kwargs)
        self.created = super(AttckTools, self)._set_attribute(kwargs, 'created')
        self.modified = super(AttckTools, self)._set_attribute(kwargs, 'modified')
        self.stix = super(AttckTools, self)._set_attribute(kwargs, 'id')
        self.type = super(AttckTools, self)._set_attribute(kwargs, 'type')
        self.wiki = super(AttckTools, self)._set_wiki(kwargs)
        self.contributor = super(AttckTools, self)._set_attribute(kwargs, 'contributor')


    @property
    def techniques(self):
        '''Returns all technique objects as a list that this tool has been identified or used'''
        from technique import AttckTechnique
        technique_list = []
        for item in self.attck_obj['objects']:
            if 'relationship_type' in item:
                if 'uses' in item['relationship_type']:
                    if self.stix in item['source_ref']:
                        if 'attack-pattern' in item['target_ref']:
                            for o in self.attck_obj['objects']:
                                if item['target_ref'] in o['id']:
                                    technique_list.append(AttckTechnique(**o))
        return technique_list

    @property
    def actors(self):
        '''Returns all actor objects as a list that are documented to use this tool'''
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