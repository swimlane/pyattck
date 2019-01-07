from attckobject import AttckObject

class AttckSoftware(AttckObject):
    """A child class of AttckObject
       Creates objects which have been categorized as software used in attacks
    
    Arguments:
        AttckObject (dict) -- Takes the Mitre ATT&CK Json object as a kwargs values
    """

    def __init__(self, **kwargs):
        """Creates an AttckSoftware object.  
           The AttckSoftware object is based on software which have been categorized as software used in attacks
        """

        self.id = super(AttckSoftware, self)._set_id(kwargs)
        self.name = super(AttckSoftware, self)._set_attribute(kwargs, 'name')
        self.alias = super(AttckSoftware, self)._set_attribute(kwargs, 'aliases')
        self.description = super(AttckSoftware, self)._set_attribute(kwargs, 'description')
        self.reference = super(AttckSoftware, self)._set_reference(kwargs)
        self.created = super(AttckSoftware, self)._set_attribute(kwargs, 'created')
        self.modified = super(AttckSoftware, self)._set_attribute(kwargs, 'modified')
        self.stix = super(AttckSoftware, self)._set_attribute(kwargs, 'id')
        self.type = super(AttckSoftware, self)._set_attribute(kwargs, 'type')
        self.wiki = super(AttckSoftware, self)._set_wiki(kwargs)
        self.contributor = super(AttckSoftware, self)._set_attribute(kwargs, 'contributor')