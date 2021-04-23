import datetime, json, os
import requests

from .adversaryemulation import AdversaryEmulation
from .atomicredteam import AtomicRedTeam
from .stockpile import MitreStockpile
from .threathuntingtables import ThreatHuntingTables
from .sysmonhunter import SysmonHunter
from .blueteamlabs import BlueTeamLabs
from .atomicthreatcoverage import AtomicThreatCoverage
from .osqueryattack import OsqueryAttack
from .attckempire import AttckEmpire
from .threathuntingbook import ThreatHuntingBook
from .nsmattck import NSMAttck
from .litmustest import LitmusTest
from .c2matrix import C2Matrix
from .aptthreattracking import APTThreatTracking
from .elemental import ElementalAttack
from .malwarearchaeology import MalwareArchaeology
from .newbeeattackdata import NewBeeAttackDataset


class GenerateAttcks(object):

    __conversion_file = os.path.abspath(os.path.join(os.path.dirname(__file__), 'conversion' + '.json'))
    conversion_data = None

    def __init__(self):
        self._datasets = {}
        self._datasets['last_updated'] = datetime.datetime.now().isoformat()
        self._datasets['techniques'] = []
        self.conversion_data = self.__get_conversion_data()

    def __get_conversion_data(self):
        if not self.conversion_data:
            try:
                with open(self.__conversion_file, 'r') as file:
                    self.conversion_data = json.load(file)
            except:
                self.conversion_data = requests.get('https://github.com/swimlane/pyattck/blob/master/generateattcks/generateattcks/conversion.json?raw=true').json()
        return self.conversion_data

    def get(self):
        self.add_adversary_emulation()
        self.add_atomic_red_team()
        self.add_mitre_stockpile()
        self.add_threat_hunting_tables()
        self.add_sysmon_hunter()
        self.add_blue_team_labs()
        self.add_atomic_threat_coverage()
        self.add_osquery_attack()
        self.add_attck_empire()
        self.add_threat_hunting_book()
        self.add_nsm_attck()
        self.add_litmust_test()
        self.add_c2_matrix()
        self.add_apt_threat_tracking()
        self.add_elemental_attack()
        self.add_malware_archaeology()
        self.add_new_bee_attack_data()
        technique_list = []
        for technique in self._datasets['techniques']:
            if self.conversion_data.get(technique['technique_id']):
                for t in self.conversion_data[technique['technique_id']]:
                    clone_technique = technique
                    clone_technique['technique_id'] = t
                    technique_list.append(clone_technique)
            else:
                technique_list.append(technique)
                
                            
        self._datasets['techniques'] = technique_list
        return self._datasets

    def add_new_bee_attack_data(self):
        for item in NewBeeAttackDataset().get():
            self.__add_to_output(item)

    def add_malware_archaeology(self):
        for item in MalwareArchaeology().get():
            self.__add_to_output(item)

    def add_elemental_attack(self):
        for item in ElementalAttack().get():
            self.__add_to_output(item)

    def add_apt_threat_tracking(self):
        apt_threat_tracking = APTThreatTracking().get()
        for item in apt_threat_tracking:
            if item:
                for key,val in item.items():
                    if key == 'malware':
                        self._datasets['tools'] = val
                        del item[key]
                        break
        self._datasets['actors'] = apt_threat_tracking

    def add_c2_matrix(self):
        c2_dict = {}
        c2 = C2Matrix().get()
        for item in c2['c2_data']:
            c2_dict[item['name']] = item['data']
        self._datasets['c2_data'] = c2_dict

    def save(self):
        with open('generated_attck_data.json', 'w') as f:
            f.write(json.dumps(self.get()))

    def add_adversary_emulation(self):
        for item in AdversaryEmulation().get():
            self.__add_to_output(item)

    def add_atomic_red_team(self):
        for item in AtomicRedTeam().get():
            self.__add_to_output(item)

    def add_mitre_stockpile(self):
        stockpile = MitreStockpile()
        stockpile.run()
        for item in stockpile.get_stockpile():
            self.__add_to_output(item)

    def add_threat_hunting_tables(self):
        for item in ThreatHuntingTables().get():
            self.__add_to_output(item)

    def add_sysmon_hunter(self):
        for item in SysmonHunter().get():
            self.__add_to_output(item)

    def add_blue_team_labs(self):
        for item in BlueTeamLabs().get():
            self.__add_to_output(item)

    def add_atomic_threat_coverage(self):
        for item in AtomicThreatCoverage().get():
            self.__add_to_output(item)

    def add_osquery_attack(self):
        for item in OsqueryAttack().get():
            self.__add_to_output(item)

    def add_attck_empire(self):
        for item in AttckEmpire().get():
            self.__add_to_output(item)

    def add_threat_hunting_book(self):
        for item in ThreatHuntingBook().get():
            self.__add_to_output(item)

    def add_nsm_attck(self):
        for item in NSMAttck().get():
            self.__add_to_output(item)

    def add_litmust_test(self):
        for item in LitmusTest().get():
            self.__add_to_output(item)

    def __add_to_output(self, data):
        status = False
        for t in self._datasets['techniques']:
            if 'technique_id' in data:
                if data['technique_id'].startswith('T') and len(data['technique_id']) == 5:
                    if data['technique_id'] == t['technique_id']:
                        status = True
                        if 'commands' in data:
                            if 'commands' not in t:
                                t['commands'] = []
                            for item in data['commands']:
                                t['commands'].append(item)
                        if 'parsed_datasets' in data:
                            if 'parsed_datasets' not in t:
                                t['parsed_datasets'] = []
                            for item in data['parsed_datasets']:
                                t['parsed_datasets'].append(item)
                        if 'command_list' in data:
                            if 'command_list' not in t:
                                t['command_list'] = []
                            for item in data['command_list']:
                                t['command_list'].append(item)
                        if 'attack_paths' in data:
                            if 'attack_paths' not in t:
                                t['attack_paths'] = []
                            for item in data['attack_paths']:
                                t['attack_paths'].append(item)
                        if 'queries' in data:
                            if 'queries' not in t:
                                t['queries'] = []
                            for item in data['queries']:
                                t['queries'].append(item)
                        if 'possible_detections' in data:
                            if 'possible_detections' not in t:
                                t['possible_detections'] = []
                            for item in data['possible_detections']:
                                t['possible_detections'].append(item)
                        if 'external_reference' in data:
                            if 'external_reference' not in t:
                                t['external_reference'] = []
                            for item in data['external_reference']:
                                t['external_reference'].append(item)

        if not status:
            if 'technique_id' in data:
                self._datasets['techniques'].append({
                    'technique_id': data['technique_id'],
                    'commands': [] if 'commands' not in data else data['commands'],
                    'parsed_datasets': [] if 'parsed_datasets' not in data else data['parsed_datasets'],
                    'command_list': [] if 'command_list' not in data else data['command_list'],
                    'attack_paths': [] if 'attack_paths' not in data else data['attack_paths'],
                    'queries': [] if 'queries' not in data else data['queries'],
                    'possible_detections': [] if 'possible_detections' not in data else data['possible_detections'],
                    'external_reference': [] if 'external_reference' not in data else data['external_reference']
                })