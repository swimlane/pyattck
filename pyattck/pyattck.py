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
    put_call_mapping = {
        AttckActor: 'put_actors',
        AttckMalware: 'put_malwares',
        AttckMitigation: 'put_mitigations',
        AttckTactic: 'put_tactics',
        AttckTechnique: 'put_techniques',
        AttckTools: 'put_tools',
    }

    def __init__(self, local_file_path=None):
        """
        Arguments:
            local_file_path (str) -- Path where json is placed
        """
        self.local_file_path = local_file_path
        self._actors = {}
        self._attck = {}
        self._mitigations = {}
        self._malwares = {}
        self._tactics = {}
        self._techniques = {}
        self._tools = {}
        self._relations = defaultdict(set)
        self.load_file()
        self.parse()

    def parse(self):
        objs = self._attck.get('objects', [])

        try:
            while True:
                obj = objs.pop()
                obj_type = obj.get('type', '')
                if obj_type in self.type_mapping:
                    cls = self.type_mapping.get(obj_type)
                    new_obj = cls(**obj)
                    if cls == AttckActor:
                        self.put_actor(new_obj)
                    elif cls == AttckMalware:
                        self.put_malware(new_obj)
                    elif cls == AttckMitigation:
                        self.put_mitigation(new_obj)
                    elif cls == AttckTactic:
                        self.put_tactic(new_obj)
                    elif cls == AttckTechnique:
                        self.put_technique(new_obj)
                    elif cls == AttckTools:
                        self.put_tools(new_obj)

                    if new_obj.stix in self._relations:
                        for rel_stix in self._relations[new_obj.stix]:
                            self._link_relations(new_obj.stix, rel_stix)
                        del self._relations[new_obj.stix]

                if 'relationship_type' in obj:
                    self._put_relations(obj['source_ref'], obj['target_ref'])
        except (IndexError, KeyError):
            pass

    def lost_relations(self):
        return self._relations

    def _get_object_by_stix(self, stix):
        type_ = stix.split('--')[0]
        if type_ == 'intrusion-set':
            return self._actors.get(stix, None)
        elif type_ == 'malware':
            return self._malwares.get(stix, None)
        elif type_ == 'course-of-action':
            return self._mitigations.get(stix, None)
        elif type_ == 'x-mitre-tactic':
            return self._tactics.get(stix, None)
        elif type_ == 'attack-pattern':
            return self._techniques.get(stix, None)
        elif type_ == 'tool':
            return self._tools.get(stix, None)

    def _link_relations(self, source, target):
        soc_obj = self._get_object_by_stix(source)
        tar_obj = self._get_object_by_stix(target)
        if soc_obj and tar_obj:
            func_name = self.put_call_mapping.get(soc_obj.__class__, '')
            func = getattr(tar_obj, func_name, None)
            if func:
                func(soc_obj)
            func_name = self.put_call_mapping.get(tar_obj.__class__, '')
            func = getattr(soc_obj, func_name, None)
            if func:
                func(tar_obj)
        return soc_obj, tar_obj

    def _put_relations(self, source, target):
        soc_obj, tar_obj = self._link_relations(source, target)
        if not soc_obj:
            self._relations[source].add(target)
        if not tar_obj:
            self._relations[target].add(source)

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

    def get_tools(self, tool_stix):
        return self._tools.get(tool_stix, None)

    def put_tools(self, tool):
        if tool.stix not in self._tools:
            self._tools[tool.stix] = tool

    def _read_file(self):
        self._attck = requests.get(__MITRE_ATTCK_JSON_URL__).json()

    def load_file(self):
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
            self._read_file()
            with open(self.local_file_path, 'w') as outfile:
                json.dump(self._attck, outfile)
        else:
            self._read_file()

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
