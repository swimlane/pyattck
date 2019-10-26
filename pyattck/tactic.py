from .attckobject import AttckObject


class AttckTactic(AttckObject):

    def __init__(self, **kwargs):
        '''The AttckTactic class is used to gather information about all Mitre ATT&CK Framework Tactics.
        To access this class directly you must first instantiate it and provide the appropriate inputs, but it is easier to use the Attck class wrapper.

        Args:
            attck_obj ([json]): This should be the raw Mitre ATT&CK json object. Defaults to None, but should be provided

        '''
        super(AttckTactic, self).__init__(**kwargs)

        self.created_by_ref = self._get_attribute('created_by_ref')
        self.external_reference = self.reference
        self.short_name = self._get_attribute('x_mitre_shortname').lower()
        self._techniques = set()

    def put_techniques(self, technique):
        self._techniques.add(technique)

    def get_techniques(self):
        '''Returns all techniques as a generator that are related to this tactic'''
        for technique in self._techniques:
            yield technique

    @property
    def techniques(self):
        '''Returns all techniques as a list that are related to this tactic'''
        return list(self._techniques)
