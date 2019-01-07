
from attckobject import AttckObject

class AttckGroup(AttckObject):
    """A child class of AttckObject
       Creates objects that are categorized as Mitre ATT&CK Groups (e.g. APT1, APT32, etc.)
    
    Arguments:
        AttckObject (dict) -- Takes the Mitre ATT&CK Json object as a kwargs values
    """


    def __init__(self, **kwargs):
        """Creates an AttckGroup object.  
           The AttckGroup object is based on categorization of Mitre ATT&CK Groups (e.g. APT1, APT32, etc.)
        """

        self.id = super(AttckGroup, self)._set_id(kwargs)
        self.name = super(AttckGroup, self)._set_attribute(kwargs, 'name')
        self.alias = super(AttckGroup, self)._set_attribute(kwargs, 'aliases')
        self.description = super(AttckGroup, self)._set_attribute(kwargs, 'description')
        self.reference = super(AttckGroup, self)._set_reference(kwargs)
        self.created = super(AttckGroup, self)._set_attribute(kwargs, 'created')
        self.modified = super(AttckGroup, self)._set_attribute(kwargs, 'modified')
        self.stix = super(AttckGroup, self)._set_attribute(kwargs, 'id')
        self.type = super(AttckGroup, self)._set_attribute(kwargs, 'type')
        self.wiki = super(AttckGroup, self)._set_wiki(kwargs)
        self.contributor = super(AttckGroup, self)._set_attribute(kwargs, 'contributor')