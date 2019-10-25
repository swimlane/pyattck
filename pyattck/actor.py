from .attckobject import AttckObject


class AttckActor(AttckObject):
    """A child class of AttckObject
       Creates objects that are categorized as Mitre ATT&CK Actors or Groups (e.g. APT1, APT32, etc.)
    
    Arguments:
        attck_obj (json) -- Takes the raw Mitre ATT&CK Json object
        AttckObject (dict) -- Takes the Mitre ATT&CK Json object as a kwargs values
    """

    def __init__(self, attck_obj, **kwargs):
        super(AttckActor, self).__init__(**kwargs)
        self.attck_obj = attck_obj

        self.created_by_ref = super(AttckActor, self)._get_attribute('created_by_ref')
        self.revoked = super(AttckActor, self)._get_attribute('revoked')
        self.aliases = super(AttckActor, self)._get_list_items('aliases')
        self.external_reference = self.reference

    def get_malwares(self):
        '''Returns all malware objects as a generator that are documented as being used by an Actor or Group
        '''
        for rel_stix in self.attck_obj.get_relations(self.stix):
            malware = self.attck_obj.get_malware(rel_stix)
            if malware:
                yield malware

    @property
    def malwares(self):
        '''Returns all malware objects as a list that are documented as being used by an Actor or Group
        '''
        return list(self.get_malwares())

    def get_tools(self):
        '''Returns all tool object as a generator that are documented as being used by an Actor or Group'''
        for rel_stix in self.attck_obj.get_relations(self.stix):
            tool = self.attck_obj.get_tools(rel_stix)
            if tool:
                yield tool

    @property
    def tools(self):
        '''Returns all tool object as a list that are documented as being used by an Actor or Group'''
        return list(self.get_tools())

    def get_techniques(self):
        '''Returns all technique objects as a generator that are documented as being used by an Actor or Group'''
        for rel_stix in self.attck_obj.get_relations(self.stix):
            technique = self.attck_obj.get_technique(rel_stix)
            if technique:
                yield technique

    @property
    def techniques(self):
        '''Returns all technique objects as a list that are documented as being used by an Actor or Group'''
        return list(self.get_techniques())
