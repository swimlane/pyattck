from attckobject import AttckObject

class AttckTactic(AttckObject):
    """A child class of AttckObject
       Creates objects which have been categorized as a tactic used by attackers
    
    Arguments:
        AttckObject (dict) -- Takes the Mitre ATT&CK Json object as a kwargs values
    """

    def __init__(self, **kwargs):
        """Creates an AttckTactic object.  
           The AttckTactic object is considered a tactic in the Mitre ATT&CK Framework
        """

        self.id = super(AttckTactic, self)._set_id(kwargs)
        self.name = super(AttckTactic, self)._set_attribute(kwargs, 'name')
        self.description = super(AttckTactic, self)._set_attribute(kwargs, 'description')
        self.reference = super(AttckTactic, self)._set_reference(kwargs)
        self.created = super(AttckTactic, self)._set_attribute(kwargs, 'created')
        self.modified = super(AttckTactic, self)._set_attribute(kwargs, 'modified')
        self.stix = super(AttckTactic, self)._set_attribute(kwargs, 'id')
        self.type = super(AttckTactic, self)._set_attribute(kwargs, 'type')
