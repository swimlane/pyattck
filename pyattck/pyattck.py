import os, json, requests
from .technique import AttckTechnique
from .actor import AttckActor
from .malware import AttckMalware
from .tools import AttckTools
from .mitigation import AttckMitigation
from .tactic import AttckTactic

__MITRE_ATTCK_JSON_URL__ = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'


class Attck(object):
    """This class creates an interface to all other classes and generates objects from the Mitre ATT&CK Framework json file.
    
    Returns:
        [Attck]: Returns a Attck object that contains all data from the Mitre ATT&CK Framework
    """

    def __init__(self, local_file_path=None):
        """
        Arguments:
            local_file_path (str) -- Path where json is placed
        """
        self.local_file_path = local_file_path
        self.attck = __MITRE_ATTCK_JSON_URL__

    @property
    def attck(self):
        return self._attck
    
    @attck.setter
    def attck(self, value):
        """Requests the Mitre ATT&CK json file
        
        Arguments:
            url (str) -- Requests the JSON via a provided URL

        Returns:
            (dict) -- Returns the requested json file
        """
        if self.local_file_path:
            if self.local_file_path.endswith('.json'):
                if not os.path.exists(os.path.dirname(self.local_file_path)):
                    os.makedirs(os.path.dirname(self.local_file_path))
            else:
                if not os.path.exists(self.local_file_path):
                    os.makedirs(self.local_file_path)
                self.local_file_path = '{}/attck.json'.format(self.local_file_path)
            self._attck = requests.get(value).json()
            with open(self.local_file_path, 'w') as outfile:
                json.dump(self._attck, outfile)
        else:
            self._attck = requests.get(value).json()


    @property
    def tactics(self):
        """Creates AttckTactic objects
        
        Returns:
            (AttckTactic) -- (Returns a iterator of AttckTactic objects)
        """
        for tactic in self.attck['objects']:
            if tactic['type'] == 'x-mitre-tactic':
                yield AttckTactic(attck_obj=self.attck, **tactic)

    @property
    def mitigations(self):
        """Creates AttckMitigation objects
        
        Returns:
            (AttckMitigation) -- (Returns a iterator of AttckMitigation objects)
        """
        for mitigation in self.attck['objects']:
            if mitigation['type'] == 'course-of-action':
                yield AttckMitigation(attck_obj=self.attck, **mitigation)
                
    @property
    def actors(self):
        """Creates AttckActor objects
        
        Returns:
            (AttckActor) -- (Returns a iterator of AttckActor objects)
        """
        for group in self.attck['objects']:
            if group['type'] == 'intrusion-set':
                yield AttckActor(attck_obj=self.attck, **group)

    @property
    def tools(self):
        """Creates AttckTools objects
        
        Returns:
            (AttckTools) -- Returns a iterator of AttckTools objects
        """
        for tools in self.attck['objects']:
            if (tools['type'] == 'tool'):
                yield AttckTools(attck_obj=self.attck, **tools)

    @property
    def malwares(self):
        """Creates AttckMalware objects
        
        Returns:
            (AttckMalware) -- Returns a iterator of AttckMalware objects
        """
        for malware in self.attck['objects']:
            if (malware['type'] == 'malware'):
                yield AttckMalware(attck_obj=self.attck, **malware)

    @property
    def techniques(self):
        """Creates AttckTechnique objects
        
        Returns:
            (AttckTechnique) -- Returns a iterator of AttckTechnique objects
        """
        for technique in self.attck["objects"]:
            if (technique['type'] == 'attack-pattern'):
                yield AttckTechnique(attck_obj=self.attck, **technique)
