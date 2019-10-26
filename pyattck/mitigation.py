from .attckobject import AttckObject


class AttckMitigation(AttckObject):
    """A child class of AttckObject
       Creates objects which have been categorized as potential mitigations
    
    Arguments:
        AttckObject (dict) -- Takes the Mitre ATT&CK Json object as a kwargs values
    """

    def __init__(self, **kwargs):
        """Creates an AttckTactic object.  
           The AttckMitigation object is considered a list of mitigations to threats based on the Mitre ATT&CK Framework
        """
        super(AttckMitigation, self).__init__(**kwargs)

        self.created_by_ref = self._get_attribute('created_by_ref')
        self.external_reference = self.reference
        self._techniques = set()

    def put_techniques(self, technique):
        self._techniques.add(technique)

    def get_techniques(self):
        '''Returns all technique objects as a generator that are related to this mitigation object'''
        for technique in self._techniques:
            yield technique

    @property
    def techniques(self):
        '''Returns all technique objects as a list that are related to this mitigation object'''
        return list(self._techniques)
