import requests, json


class GenerateNISTData:

    __NIST_MAPPINGS_URL = 'https://raw.githubusercontent.com/center-for-threat-informed-defense/attack-control-framework-mappings/master/frameworks/nist800-53-r4/stix/nist800-53-r4-mappings.json'
    __NIST_CONTROLS_URL = 'https://raw.githubusercontent.com/center-for-threat-informed-defense/attack-control-framework-mappings/master/frameworks/nist800-53-r4/stix/nist800-53-r4-controls.json'
    __NIST_MAPPINGS_DATA = None
    __NIST_CONTROLS_DATA = None

    def __get_mappings_data(self):
        if not self.__NIST_MAPPINGS_DATA:
            mappings_response = requests.get(self.__NIST_MAPPINGS_URL).json()
            self.__NIST_MAPPINGS_DATA = json.loads(json.dumps(mappings_response))['objects']
        return self.__NIST_MAPPINGS_DATA

    def __get_controls_data(self):
        if not self.__NIST_CONTROLS_DATA:
            response = requests.get(self.__NIST_CONTROLS_URL).json()
            self.__NIST_CONTROLS_DATA = json.loads(json.dumps(response))['objects']
        return self.__NIST_CONTROLS_DATA

    def get(self):
        return_dict = {}
        mappings = self.get_nist_mappings()
        controls = self.get_nist_control_relationships()
        for attack_pattern, course_of_actions in mappings.items():
            if attack_pattern not in return_dict:
                return_dict[attack_pattern] = []
            
            if isinstance(course_of_actions, list):
                for course_of_action in course_of_actions:
                    if controls.get(course_of_action):
                        for control in controls[course_of_action]:
                            for obj in self.__get_controls_data():
                                if obj.get('type') == 'course-of-action' and obj.get('id') == control:
                                    return_dict[attack_pattern].append(control)
        return return_dict

    def get_nist_mappings(self):
        attack_dict = {}
        for obj in self.__get_mappings_data():
            if obj.get('target_ref') not in attack_dict:
                attack_dict[obj['target_ref']] = []
            attack_dict[obj['target_ref']].append(obj['source_ref'])
        return attack_dict

    def get_nist_control_relationships(self):
        return_dict = {}
        for obj in self.__get_controls_data():
            if obj.get('type') == 'relationship':
                if obj.get('source_ref') not in return_dict:
                    return_dict[obj['source_ref']] = []
                return_dict[obj['source_ref']].append(obj['target_ref'])

                if obj.get('target_ref') not in return_dict:
                    return_dict[obj['target_ref']] = []
                return_dict[obj['target_ref']].append(obj['source_ref'])
        return return_dict

    def save(self):
        with open('attck_to_nist_controls.json', 'w') as f:
            f.write(json.dumps(self.get()))
