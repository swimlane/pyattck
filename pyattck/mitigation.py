from .attckobject import AttckObject


class AttckMitigation(AttckObject):
    """A child class of AttckObject
       Creates objects which have been categorized as potential mitigations
    
    Arguments:
        AttckObject (dict) -- Takes the Mitre ATT&CK Json object as a kwargs values
    """

    def __init__(self, attck_obj, **kwargs):
        """Creates an AttckTactic object.  
           The AttckMitigation object is considered a list of mitigations to threats based on the Mitre ATT&CK Framework
        """
        super(AttckMitigation, self).__init__(**kwargs)
        self.attck_obj = attck_obj

        self.created_by_ref = self._get_attribute('created_by_ref')
        self.external_reference = self.reference

    def get_techniques(self):
        '''Returns all technique objects as a generator that are related to this mitigation object'''
        for rel_stix in self.attck_obj.get_relations(self.stix):
            technique = self.attck_obj.get_technique(rel_stix)
            if technique:
                yield technique

    @property
    def techniques(self):
        '''Returns all technique objects as a list that are related to this mitigation object'''
        return list(self.get_techniques())
