import yaml
import os


class Configuration(object):

    """
    This class will set and get a config.yml file which contains the
    location of data json files used by pyattck.

    Returns:
        Configuration: Will return a Configuration instance
    """

    __CONFIG_FILE = os.path.join(
        os.path.expanduser('~'), 'pyattck', 'config' + '.yml'
    )
    __DATASETS_MAP = {
        'data_path': None,
        'enterprise': {
            'url': 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json',
            'filename': 'enterprise_attck.json',
        },
        'preattck': {
            'url': 'https://raw.githubusercontent.com/mitre/cti/master/pre-attack/pre-attack.json',
            'filename': 'preattack.json',
        },
        'mobile': {
            'url': 'https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json',
            'filename': 'mobile_attck.json',
        },
        'nist_800_53_rev4_controls': {
            'url': 'https://raw.githubusercontent.com/center-for-threat-informed-defense/attack-control-framework-mappings/master/frameworks/nist800-53-r4/stix/nist800-53-r4-controls.json',
            'filename': 'enterprise_attck_nist_800_53_rev4_controls.json',
        },
        'generated_data': {
            'url': 'https://raw.githubusercontent.com/swimlane/pyattck/master/generated_attck_data.json',
            'filename': 'enterprise_attck_dataset.json',
        },
        'nist_data': {
            'url': 'https://raw.githubusercontent.com/swimlane/pyattck/master/attck_to_nist_controls_data.json',
            'filename': 'enterprise_attck_nist_data.json',
        }
    }

    def get(self):
        """Calling the get method will return configuration settings within the config.yml file

        Returns:
            dict: A dictionary containing configuration settings
        """        
        if os.path.isfile(self.__CONFIG_FILE):
            with open(self.__CONFIG_FILE) as f:
                config = yaml.load(f, Loader=yaml.FullLoader)
                if not config:
                    self.set()
                    return self.get()
                else:
                    return config
        else:
            self.set()
            return self.get()

    def set(self, enterprise_attck_json_path=None, preattck_json_path=None, mobile_attck_json_path=None, enterprise_attck_dataset_path=None):
        """This method will set pyattcks configuration file settings.

        If no config.yml is found, it will generate one with default settings
        
        Args:
            enterprise_attck_json_path (str, optional): Path to store the Enterprise MITRE ATT&CK JSON data file. Defaults to None.
            preattck_json_path (str, optional): Path to store the MITRE PRE-ATT&CK JSON data file. Defaults to None.
            mobile_attck_json_path (str, optional): Path to store the MITRE Mobile ATT&CK JSON data file. Defaults to None.
            enterprise_attck_dataset_path (str, optional): Path to store the Enterprise MITRE ATT&CK Generated JSON data file. Defaults to None.
        """        
        config = {}
        if enterprise_attck_json_path:
            if '.json' not in enterprise_attck_json_path:
                config['enterprise_attck_json'] = '{}/enterprise_attck.json'.format(self.__get_absolute_path(enterprise_attck_json_path))
            else:
                config['enterprise_attck_json'] = self.__get_absolute_path(enterprise_attck_json_path)
        else:
            config['enterprise_attck_json'] = os.path.join(os.path.expanduser('~'), 'pyattck', 'enterprise_attck' + '.json')

        
        if preattck_json_path:
            if '.json' not in preattck_json_path:
                config['preattck_json'] = '{}/preattack.json'.format(self.__get_absolute_path(preattck_json_path))
            else:
                config['preattck_json'] = self.__get_absolute_path(preattck_json_path)
        else:
            config['preattck_json'] = os.path.join(os.path.expanduser('~'), 'pyattck', 'preattck' + '.json')
        

        if mobile_attck_json_path:
            if '.json' not in mobile_attck_json_path:
                config['mobile_attck_json'] = '{}/mobile_attck.json'.format(self.__get_absolute_path(mobile_attck_json_path))
            else:
                config['mobile_attck_json'] = self.__get_absolute_path(mobile_attck_json_path)
        else:
            config['mobile_attck_json'] = os.path.join(os.path.expanduser('~'), 'pyattck', 'mobile_attck' + '.json')


        if enterprise_attck_dataset_path:
            if '.json' not in enterprise_attck_dataset_path:
                config['enterprise_attck_dataset'] = '{}/enterprise_attck_dataset.json'.format(self.__get_absolute_path(enterprise_attck_dataset_path))
            else:
                config['enterprise_attck_dataset'] = self.__get_absolute_path(enterprise_attck_dataset_path)
        else:
            config['enterprise_attck_dataset'] = os.path.join(os.path.expanduser('~'), 'pyattck', 'enterprise_attck_dataset' + '.json')

    
        self.__write_config(config)

    def __get_absolute_path(self, value):
        return os.path.abspath(value)

    def __write_config(self, config):
        mode = None
        if not os.path.exists(self.__CONFIG_FILE):
            mode = 'w+'
            os.makedirs(os.path.dirname(self.__CONFIG_FILE))
        else:
            mode = 'w'
        with open(self.__CONFIG_FILE, mode) as outfile:
            document = yaml.dump(config, outfile)