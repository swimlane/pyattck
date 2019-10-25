import os, json, requests

from collections import defaultdict

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

    type_mapping = {
        'intrusion-set': AttckActor,
        'malware': AttckMalware,
        'course-of-action': AttckMitigation,
        'x-mitre-tactic': AttckTactic,
        'attack-pattern': AttckTechnique,
        'tool': AttckTools,
    }

    def __init__(self, local_file_path=None):
        """
        Arguments:
            local_file_path (str) -- Path where json is placed
        """
        self.local_file_path = local_file_path
        self.attck = __MITRE_ATTCK_JSON_URL__
        self._tactics = {}
        self._mitigations = {}
        self._actors = {}
        self._malwares = {}
        self._techniques = {}
        self._tools = {}
        self._relations = defaultdict(list)
        self.load()

    def load(self):
        for obj in self.attck.get('objects', []):
            obj_type = obj.get('type', '')
            if obj_type in self.type_mapping:
                cls = self.type_mapping.get(obj_type)
                new_obj = cls(self, **obj)
                if cls == AttckActor:
                    self.put_actor(new_obj)
                elif cls == AttckMalware:
                    self.put_malware(new_obj)
                elif cls == AttckMitigation:
                    self.put_mitigation(new_obj)
                elif cls == AttckTactic:
                    self.put_tactic(new_obj)
                elif cls == AttckTools:
                    self.put_tools(new_obj)

            if 'relationship_type' in obj:
                source = obj['source_ref']
                target = obj['target_ref']
                self._relations[source].append(target)
                self._relations[target].append(source)

    def get_relations(self, relation_type, stix):
        if relation_type in self._relations:
            return self._relations[relation_type][stix]

    def get_actor(self, actor_stix):
        return self._actors.get(actor_stix, None)

    def put_actor(self, actor):
        if actor.stix not in self._actors:
            self._actors[actor.stix] = actor

    def get_malware(self, malware_stix):
        return self._malwares.get(malware_stix, None)

    def put_malware(self, malware):
        if malware.stix not in self._malwares:
            self._malwares[malware.stix] = malware

    def get_mitigation(self, mitigation_stix):
        return self._mitigations.get(mitigation_stix, None)

    def put_mitigation(self, mitigation):
        if mitigation.stix not in self._mitigations:
            self._mitigations[mitigation.stix] = mitigation

    def get_tactic(self, tactic_stix):
        return self._tactics.get(tactic_stix, None)

    def put_tactic(self, tactic):
        if tactic.stix not in self._tactics:
            self._tactics[tactic.stix] = tactic

    def get_technique(self, technique_stix):
        return self._techniques.get(technique_stix, None)

    def put_technique(self, technique):
        if technique.stix not in self._techniques:
            self._techniques[technique.stix] = technique

    def get_tool(self, tool_stix):
        return self._tools.get(tool_stix, None)

    def put_tools(self, tool):
        if tool.stix not in self._tools:
            self._tools[tool.stix] = tool

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
            (AttckTactic) -- (Returns a generator of AttckTactic objects)
        """
        return self._tactics.values()

    @property
    def mitigations(self):
        """Creates AttckMitigation objects
        
        Returns:
            (AttckMitigation) -- (Returns a generator of AttckMitigation objects)
        """
        return self._mitigations.values()

    @property
    def actors(self):
        """Creates AttckActor objects
        
        Returns:
            (AttckActor) -- (Returns a generator of AttckActor objects)
        """
        return self._actors.values()

    @property
    def tools(self):
        """Creates AttckTools objects
        
        Returns:
            (AttckTools) -- Returns a generator of AttckTools objects
        """
        return self._tools.values()

    @property
    def malwares(self):
        """Creates AttckMalware objects
        
        Returns:
            (AttckMalware) -- Returns a generator of AttckMalware objects
        """
        return self._malwares.values()

    @property
    def techniques(self):
        """Creates AttckTechnique objects
        
        Returns:
            (AttckTechnique) -- Returns a generator of AttckTechnique objects
        """
        return self._techniques.values()
