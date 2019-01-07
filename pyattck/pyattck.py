
try:
    # For Python 3.0 and later
    from urllib.request import urlopen
except ImportError:
    # Fall back to Python 2's urllib2
    from urllib2 import urlopen

import json, requests
from attcktechnique import AttckTechnique
from attckgroup import AttckGroup
from attcksoftware import AttckSoftware
from attcktactic import AttckTactic
from attckobject import AttckObject

__MITRE_ATTCK_JSON_URL__ = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'


class Attck(object):
    def __init__(self):
        self.attck_json = self.get_attck_json(__MITRE_ATTCK_JSON_URL__)
        self.attck_tactic = self._set_attck_tactic_object()
        self.attck_group = self._set_attck_group_object()
        self.attck_software = self._set_attck_software_object()
        self.attck_technique = self.set_attck_technique()

    def get_attck_json(self, url):
        """Requests the Mitre ATT&CK json file
        
        Arguments:
            url (str) -- Requests the JSON via a provided URL

        Returns:
            (dict) -- Returns the requested json file
        """

        return(requests.get(url).json())

    def _set_attck_tactic_object(self):
        """Creates AttckTactic objects
        
        Returns:
            (AttckTactic) -- Returns a list of AttckTactic objects
        """

        tactic_list = []
        for tactic in self.attck_json['objects']:
            if tactic['type'] == 'course-of-action':
                tactic_list.append(AttckTactic(**tactic))
        return tactic_list
                
    def _set_attck_group_object(self):
        """Creates AttckGroup objects
        
        Returns:
            (AttckGroup) -- (Returns a list of AttckGroup objects)
        """
        group_list = []
        for group in self.attck_json['objects']:
            if group['type'] == 'intrusion-set':
                group_list.append(AttckGroup(**group))
        return group_list

    def _set_attck_software_object(self):
        """Creates AttckSoftware objects
        
        Returns:
            (AttckSoftware) -- Returns a list of AttckSoftware objects
        """
        software_list = []
        for tactic in self.attck_json['objects']:
            if (tactic['type'] == 'tool') or (tactic['type'] == 'malware'):
                software_list.append(AttckSoftware(**tactic))
        return software_list

    def set_attck_technique(self):
        """Creates AttckTechnique objects
        
        Returns:
            (AttckTechnique) -- Returns a list of AttckTechnique objects
        """
        return_objects = []
        for key in self.attck_json["objects"]:
            return_objects.append(AttckTechnique(self.attck_tactic, **key))
        return return_objects