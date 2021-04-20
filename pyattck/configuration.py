import yaml
import os


class Configuration(object):

    """Sets and gets configuration details.

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
            'url': 'https://github.com/swimlane/pyattck/blob/master/generated_attck_data.json?raw=True',
            'filename': 'enterprise_attck_dataset.json',
        },
        'nist_data': {
            'url': 'https://github.com/swimlane/pyattck/blob/master/attck_to_nist_controls.json?raw=True',
            'filename': 'enterprise_attck_nist_data.json',
        }
    }

    def get(self):
        """
        Calling the get method will return configuration settings within
        the config.yml file

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

    def set(self, data_path=None):
        """
        This method will set pyattcks configuration file settings.

        If no config.yml is found, it will generate one with default settings

        Args:
            data_path (str, optional): Path to store all external data.
                                       Defaults to ~/pyattck.
        """
        if data_path and data_path != '~':
            self.__DATASETS_MAP['data_path'] = os.path.abspath(data_path)
        else:
            self.__DATASETS_MAP['data_path'] = os.path.join(os.path.expanduser('~'), 'pyattck')

        self.__write_config(self.__DATASETS_MAP)

    def __write_config(self, config):
        mode = None
        if not os.path.exists(self.__CONFIG_FILE):
            mode = 'w+'
            os.makedirs(os.path.dirname(self.__CONFIG_FILE))
        else:
            mode = 'w'
        with open(self.__CONFIG_FILE, mode) as outfile:
            document = yaml.dump(config, outfile)
