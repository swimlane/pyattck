import json, requests
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

    def __init__(self):
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
        self._attck = requests.get(value).json()

    @property
    def tactics(self):
        """Creates AttckTactic objects
        
        Returns:
            (AttckTactic) -- (Returns a list of AttckTactic objects)
        """
        tactic_list = []
        for tactic in self.attck['objects']:
            if tactic['type'] == 'x-mitre-tactic':
                tactic_list.append(AttckTactic(attck_obj=self.attck, **tactic))
        return tactic_list

    @property
    def mitigations(self):
        """Creates AttckMitigation objects
        
        Returns:
            (AttckMitigation) -- (Returns a list of AttckMitigation objects)
        """
        mitigation_list = []
        for mitigation in self.attck['objects']:
            if mitigation['type'] == 'course-of-action':
                mitigation_list.append(AttckMitigation(attck_obj=self.attck, **mitigation))
        return mitigation_list
                
    @property
    def actors(self):
        """Creates AttckActor objects
        
        Returns:
            (AttckActor) -- (Returns a list of AttckActor objects)
        """
        group_list = []
        for group in self.attck['objects']:
            if group['type'] == 'intrusion-set':
                group_list.append(AttckActor(attck_obj=self.attck, **group))
        return group_list

    @property
    def tools(self):
        """Creates AttckTools objects
        
        Returns:
            (AttckTools) -- Returns a list of AttckTools objects
        """
        tools_list = []
        for tools in self.attck['objects']:
            if (tools['type'] == 'tool'):
                tools_list.append(AttckTools(attck_obj=self.attck, **tools))
        return tools_list

    @property
    def malwares(self):
        """Creates AttckMalware objects
        
        Returns:
            (AttckMalware) -- Returns a list of AttckMalware objects
        """
        malware_list = []
        for malware in self.attck['objects']:
            if (malware['type'] == 'malware'):

                malware_list.append(AttckMalware(attck_obj=self.attck, **malware))
        return malware_list

    @property
    def techniques(self):
        """Creates AttckTechnique objects
        
        Returns:
            (AttckTechnique) -- Returns a list of AttckTechnique objects
        """
        technique_list = []
        for technique in self.attck["objects"]:
            if (technique['type'] == 'attack-pattern'):
                technique_list.append(AttckTechnique(attck_obj=self.attck, **technique))
        return technique_list