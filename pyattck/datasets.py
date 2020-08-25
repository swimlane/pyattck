import requests, json, pendulum, os
from .configuration import Configuration


class AttckDatasets(object):

    """AttckDatasets is used to download, save or retrieve datasets for pyattck.

        Default locations to download datasets are as follows:
            MITRE_ATTCK_JSON_URL = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
            MITRE_PREATTCK_ATTCK_JSON_URL  = 'https://raw.githubusercontent.com/mitre/cti/master/pre-attack/pre-attack.json'
            MITRE_MOBILE_ATTCK_JSON_URL = 'https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json'
            DATASETS_URL = 'https://raw.githubusercontent.com/swimlane/pyattck/master/generated_attck_data.json'
    """    

    __MITRE_ENTERPRISE_ATTCK_JSON_URL = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
    __MITRE_PREATTCK_ATTCK_JSON_URL  = 'https://raw.githubusercontent.com/mitre/cti/master/pre-attack/pre-attack.json'
    __MITRE_MOBILE_ATTCK_JSON_URL = 'https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json'
    __DATASETS_URL = 'https://raw.githubusercontent.com/swimlane/pyattck/master/generated_attck_data.json'

    def __init__(self):
        config = Configuration().get()
        self.attck_json_path = config['enterprise_attck_json']
        self.preattck_json_path = config['preattck_json']
        self.mobile_attck_json_path = config['mobile_attck_json']
        self.dataset_json_path = config['enterprise_attck_dataset']


    def __get_mitre_json(self, url, path, force=False):
        if force:
            mitre = requests.get(url).json()
            self.__save_locally(path, mitre)
            return mitre
        else:
            cached_data = self.__get_cached_data(path)
            if cached_data:
                return cached_data
            else:
                mitre = requests.get(url).json()
                self.__save_locally(path, mitre)
                return mitre

    def mitre(self, type='enterprise', force=False):
        """Downloads, saves, or retrieves MITRE ATT&CK Framework JSON files
        
        Args:
            type (str, optional): Will set the type of data to download/retrieve.  Defaults to Enterprise.  Options are enterprise, preattack, & mobile
            force (bool, optional): Will force the download of a new JSON file. Defaults to False.
        
        Returns:
            [dict]: Mitre ATT&CK Enterprise Framework JSON
        """
        # first check to see if it already exists
        if type == 'enterprise':
            url = self.__MITRE_ENTERPRISE_ATTCK_JSON_URL
            return self.__get_mitre_json(url, self.attck_json_path, force=force)
        elif type == 'preattack':
            url = self.__MITRE_PREATTCK_ATTCK_JSON_URL
            return self.__get_mitre_json(url, self.preattck_json_path, force=force)
        elif type == 'mobile':
            url = self.__MITRE_MOBILE_ATTCK_JSON_URL
            return self.__get_mitre_json(url, self.mobile_attck_json_path, force=force)
        else:
            url = self.__MITRE_ENTERPRISE_ATTCK_JSON_URL
            return self.__get_mitre_json(url, self.attck_json_path, force=force)


    def generated_attck_data(self, force=False):
        """Downloads, saves, or retrieves the Mitre ATT&CK Enterprise Generated Dataset JSON
        
        Args:
            force (bool, optional): Will force the download of a new Generated Datset JSON file. Defaults to False.
        
        Returns:
            [dict]: Mitre ATT&CK Enterprise Generated Dataset JSON
        """
        if force:
            datasets = self.__get_datasets()
            self.__save_locally(self.dataset_json_path, datasets)
            return datasets
        else:
            cached_data = self.__get_cached_data(self.dataset_json_path)
            if cached_data:
                if pendulum.now().add(days=30).to_iso8601_string() >= pendulum.parse(cached_data['last_updated']).to_iso8601_string():
                    return cached_data
                else:
                    datasets = requests.get(self.__DATASETS_URL).json()
                    self.__save_locally(self.dataset_json_path, datasets)
                    return datasets
            else:
                datasets = requests.get(self.__DATASETS_URL)
                if datasets:
                    try:
                        datasets = datasets.json()
                    except:
                        print('Unable to downlad and load external datasets')
                        pass
                self.__save_locally(self.dataset_json_path, datasets)
                return datasets

    def __get_datasets(self):
        return requests.get(self.__DATASETS_URL).json()

    def __get_cached_data(self, local_file_path):
        if os.path.isfile(local_file_path):
            with open(local_file_path) as f:
                try:
                    return json.load(f)
                except:
                    pass
        else:
            return None

    def __save_locally(self, local_file_path, data):
        with open(local_file_path, 'w+') as outfile:
            try:
                json.dump(data, outfile)
            except:
                pass