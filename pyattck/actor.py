from .attckobject import AttckObject


class AttckActor(AttckObject):
    """A child class of AttckObject
       Creates objects that are categorized as Mitre ATT&CK Actors or Groups (e.g. APT1, APT32, etc.)
    
    Arguments:
        attck_obj (json) -- Takes the raw Mitre ATT&CK Json object
        AttckObject (dict) -- Takes the Mitre ATT&CK Json object as a kwargs values
    """

    def __init__(self, **kwargs):
        super(AttckActor, self).__init__(**kwargs)

        self.created_by_ref = self._get_attribute('created_by_ref')
        self.revoked = self._get_attribute('revoked')
        self.aliases = self._get_list_items('aliases')
        self.external_reference = self.reference
        self._malwares = set()
        self._tools = set()
        self._techniques = set()

    def put_malwares(self, malware):
        self._malwares.add(malware)

    def get_malwares(self):
        '''Returns all malware objects as a generator that are documented as being used by an Actor or Group
        '''
        for malware in self._malwares:
            yield malware

    @property
    def malwares(self):
        '''Returns all malware objects as a list that are documented as being used by an Actor or Group
        '''
        return list(self._malwares)

    def put_tools(self, tool):
        self._tools.add(tool)

    def get_tools(self):
        '''Returns all tool object as a generator that are documented as being used by an Actor or Group'''
        for tool in self._tools:
            yield tool

    @property
    def tools(self):
        '''Returns all tool object as a list that are documented as being used by an Actor or Group'''
        return list(self._tools)

    def put_techniques(self, technique):
        self._techniques.add(technique)

    def get_techniques(self):
        '''Returns all technique objects as a generator that are documented as being used by an Actor or Group'''
        for technique in self._techniques:
            yield technique

    @property
    def techniques(self):
        '''Returns all technique objects as a list that are documented as being used by an Actor or Group'''
        return list(self._techniques)
