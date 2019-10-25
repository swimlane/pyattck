from .attckobject import AttckObject


class AttckTools(AttckObject):
    """A child class of AttckObject
       Creates objects which have been categorized as software used in attacks
    
    Arguments:
        AttckObject (dict) -- Takes the Mitre ATT&CK Json object as a kwargs values
    """

    def __init__(self, attck_obj, **kwargs):
        """Creates an AttckTools object.  
           The AttckTools object is based on software which have been categorized as software used in attacks
        """
        super(AttckTools, self).__init__(**kwargs)
        self.attck_obj = attck_obj

        self.alias = self._get_attribute('aliases')
        self.contributor = self._get_attribute('contributor')
        self._techniques = []

    def get_techniques(self):
        '''Returns all technique objects as a generator that this tool has been identified or used'''
        for rel_stix in self.attck_obj.get_relations(self.stix):
            technique = self.attck_obj.get_technique(rel_stix)
            if technique:
                yield technique

    @property
    def techniques(self):
        '''Returns all technique objects as a list that this tool has been identified or used'''
        return list(self.get_techniques())

    def get_actors(self):
        '''Returns all actor objects as a generator that are documented to use this tool'''
        for rel_stix in self.attck_obj.get_relations(self.stix):
            actor = self.attck_obj.get_actor(rel_stix)
            if actor:
                yield actor

    @property
    def actors(self):
        '''Returns all actor objects as a list that are documented to use this tool'''
        return list(self.get_actors())
