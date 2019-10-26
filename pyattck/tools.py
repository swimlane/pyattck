from .attckobject import AttckObject


class AttckTools(AttckObject):
    """A child class of AttckObject
       Creates objects which have been categorized as software used in attacks
    
    Arguments:
        AttckObject (dict) -- Takes the Mitre ATT&CK Json object as a kwargs values
    """

    def __init__(self, **kwargs):
        """Creates an AttckTools object.  
           The AttckTools object is based on software which have been categorized as software used in attacks
        """
        super(AttckTools, self).__init__(**kwargs)

        self.alias = self._get_attribute('aliases')
        self.contributor = self._get_attribute('contributor')
        self._actors = set()
        self._techniques = set()

    def put_techniques(self, technique):
        self._techniques.add(technique)

    def get_techniques(self):
        '''Returns all technique objects as a generator that this tool has been identified or used'''
        for technique in self._techniques:
            yield technique

    @property
    def techniques(self):
        '''Returns all technique objects as a list that this tool has been identified or used'''
        return list(self._techniques)

    def put_actors(self, actor):
        self._actors.add(actor)

    def get_actors(self):
        '''Returns all actor objects as a generator that are documented to use this tool'''
        for actor in self._actors:
            yield actor

    @property
    def actors(self):
        '''Returns all actor objects as a list that are documented to use this tool'''
        return list(self._actors)
