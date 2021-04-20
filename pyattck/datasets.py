import requests
import json
import pendulum
import os
from .configuration import Configuration


class AttckDatasets(object):

    """Retrieves and saves datasets used by pyattck.

    AttckDatasets is used to download, save or retrieve datasets for pyattck.

        Default locations to download datasets are as follows:
            MITRE_ATTCK_JSON_URL = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
            MITRE_PREATTCK_ATTCK_JSON_URL  = 'https://raw.githubusercontent.com/mitre/cti/master/pre-attack/pre-attack.json'
            MITRE_MOBILE_ATTCK_JSON_URL = 'https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json'
            DATASETS_URL = 'https://github.com/swimlane/pyattck/blob/master/generated_attck_data.json?raw=True'
            NIST_DATASETS_URL = 'https://github.com/swimlane/pyattck/blob/master/attck_to_nist_controls.json?raw=True'
    """

    def __init__(self):
        """
        The main class to retrieve and save datasets external from this package.
        """
        self.__DATASETS_MAP = Configuration().get()

    def __get_json_data(self, url, path, force=False):
        if force:
            data = requests.get(url).json()
            self.__save_locally(path, data)
            return data
        else:
            cached_data = self.__get_cached_data(path)
            if cached_data:
                if cached_data.get('last_updated'):
                    if pendulum.now().add(days=30).to_iso8601_string() >= pendulum.parse(cached_data['last_updated']).to_iso8601_string():
                        return cached_data
                    else:
                        datasets = self.__download_data(url)
                        self.__save_locally(path, datasets)
                        return datasets
                else:
                    datasets = self.__download_data(url)
                    self.__save_locally(path, datasets)
                    return datasets
            else:
                data = requests.get(url).json()
                self.__save_locally(path, data)
                return data

    def get_data(self, data_type, force=False):
        """
        Downloads, saves, or retrieves JSON data

        Args:
            type (str): Will set the type of data to download/retrieve. Options are
                        enterprise, preattack, mobile, generated_data, nist_data
            force (bool, optional): Will force the download of a new JSON file.
                                    Defaults to False.

        Returns:
            [dict]: Returns JSON data
        """
        if self.__DATASETS_MAP.get(data_type):
            return self.__get_json_data(
                self.__DATASETS_MAP[data_type]['url'],
                os.path.join(self.__DATASETS_MAP['data_path'], self.__DATASETS_MAP[data_type]['filename']),
                force=force
            )

    def __download_data(self, url):
        return requests.get(url).json()

    def __get_cached_data(self, local_file_path):
        if os.path.isfile(local_file_path):
            if os.path.getsize(local_file_path) > 0:
                with open(local_file_path) as f:
                    try:
                        return json.load(f)
                    except:
                        pass
        return None

    def __save_locally(self, local_file_path, data):
        if not data.get('last_updated'):
            data['last_updated'] = pendulum.now().to_iso8601_string()
        with open(local_file_path, 'w+') as outfile:
            try:
                json.dump(data, outfile)
            except:
                pass
