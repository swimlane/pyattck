import os
import json
from urllib.parse import urlparse
from pathlib import Path
import yaml
from requests.api import request


class ConfigurationProperties(type):

    __config_data = None

    def __download_url_data(cls, url):
        return request('GET', url, **cls.requests_kwargs).json()

    def _check_if_path(cls, value):
        if Path(value):
            return True
        return False

    def _check_if_url(cls, value):
        try:
            if urlparse(value).scheme in ['http', 'https']:
                return True
            return False
        except:
            return False

    def __get_absolute_path(cls, path_string):
        return os.path.abspath(
            os.path.expanduser(
                os.path.expandvars(path_string)
            )
        )

    def __validate_value_string(cls, value):
        if cls._check_if_url(value):
            return value
        elif cls._check_if_path(value):
            return value
        else:
            raise Exception('The provided value is neither a URL or file path')

    def __write_to_disk(cls, path, json_data):
        with open(path, 'w+') as file_obj:
            json.dump(json_data, file_obj)

    def __save_data(cls):
        if not os.path.exists(os.path.dirname(cls.data_path)):
            try:
                os.makedirs(os.path.dirname(cls.data_path))
            except:
                raise Exception(
                    'Unable to save data to the provided location: {}'.format(cls.data_path)
                )
        for json_data in ['enterprise_attck_json', 'pre_attck_json', 
                          'mobile_attck_json', 'nist_controls_json', 
                          'generated_attck_json', 'generated_nist_json']:
            if cls._check_if_url(getattr(cls, json_data)):
                path = os.path.join(cls.data_path, "{json_data}.json".format(json_data=json_data))
                data = cls.__download_url_data(getattr(cls, json_data))
                cls.__write_to_disk(path, data)

    def __save_config(cls, value):
        # save configuration to disk
        if not os.path.exists(os.path.dirname(value)):
            try:
                os.makedirs(os.path.dirname(value))
            except:
                raise Exception('pyattck attempted to create the provided directories but was unable to: {}'.format(value))
        with open(value, 'w+') as f:
            if value.endswith('.json'):
                json.dump(cls.cls.config_data, f)
            elif value.endswith('.yml'):
                yaml.dump(cls.config_data, f)

    def get_data(cls, value):
        data = None
        if os.path.isfile(value):
            with open(value) as f:
                if value.endswith('.json'):
                    data = json.load(f)
                elif value.endswith('.yml'):
                    data = yaml.load(f, Loader=yaml.FullLoader)
        elif cls._check_if_url(value):
            data = cls.__download_url_data(value)
        return data

    @property
    def requests_kwargs(cls):
        return cls._requests_kwargs

    @requests_kwargs.setter
    def requests_kwargs(cls, value):
        cls._requests_kwargs = value

    @property
    def use_config(cls):
        return cls._use_config

    @use_config.setter
    def use_config(cls, value):
        cls._use_config = bool(value)

    @property
    def save_config(cls):
        return cls._save_config

    @save_config.setter
    def save_config(cls, value):
        cls._save_config = bool(value)

    @property
    def config_file_path(cls):
        return cls.__get_absolute_path(cls._config_file_path)

    @config_file_path.setter
    def config_file_path(cls, value):
        cls._config_file_path = cls.__get_absolute_path(value)

    @property
    def data_path(cls):
        return cls.__get_absolute_path(cls._data_path)

    @data_path.setter
    def data_path(cls, value):
        cls._data_path = cls.__get_absolute_path(value)

    @property
    def config_data(cls):
        if not cls.__config_data:
            if cls.use_config:
                cls.__config_data = cls.get_data(cls.config_file_path)
            if cls.save_config:
                cls.__save_config(cls.config_file_path)
                cls.__save_data()
            if not cls.__config_data:
                cls.__config_data = {
                    'data_path': cls.data_path,
                    'enterprise_attck_json': cls._enterprise_attck_json,
                    'pre_attck_json': cls._pre_attck_json,
                    'mobile_attck_json': cls._mobile_attck_json,
                    'nist_controls_json': cls._nist_controls_json,
                    'generated_attck_json': cls._generated_attck_json,
                    'generated_nist_json': cls._generated_nist_json
                }
        if not cls.use_config and not cls.save_config:
            return {
                    'data_path': cls.data_path,
                    'enterprise_attck_json': cls._enterprise_attck_json,
                    'pre_attck_json': cls._pre_attck_json,
                    'mobile_attck_json': cls._mobile_attck_json,
                    'nist_controls_json': cls._nist_controls_json,
                    'generated_attck_json': cls._generated_attck_json,
                    'generated_nist_json': cls._generated_nist_json
                }
        return cls.__config_data

    @property
    def enterprise_attck_json(cls):
        return cls._enterprise_attck_json

    @enterprise_attck_json.setter
    def enterprise_attck_json(cls, value):
        cls._enterprise_attck_json = cls.__validate_value_string(value)

    @property
    def pre_attck_json(cls):
        return cls._pre_attck_json

    @pre_attck_json.setter
    def pre_attck_json(cls, value):
        cls._pre_attck_json = cls.__validate_value_string(value)

    @property
    def mobile_attck_json(cls):
        return cls._mobile_attck_json

    @mobile_attck_json.setter
    def mobile_attck_json(cls, value):
        cls._mobile_attck_json = cls.__validate_value_string(value)

    @property
    def nist_controls_json(cls):
        return cls._nist_controls_json

    @nist_controls_json.setter
    def nist_controls_json(cls, value):
        cls._nist_controls_json = cls.__validate_value_string(value)

    @property
    def generated_attck_json(cls):
        return cls._generated_attck_json

    @generated_attck_json.setter
    def generated_attck_json(cls, value):
        cls._generated_attck_json = cls.__validate_value_string(value)

    @property
    def generated_nist_json(cls):
        return cls._generated_nist_json

    @generated_nist_json.setter
    def generated_nist_json(cls, value):
        cls._generated_nist_json = cls.__validate_value_string(value)


class Configuration(object, metaclass=ConfigurationProperties):
    _use_config = False
    _save_config = False
    _config_file_path = '~/pyattck/config.yml'
    _data_path = '~/pyattck/data'
    _enterprise_attck_json = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    _pre_attck_json="https://raw.githubusercontent.com/mitre/cti/master/pre-attack/pre-attack.json"
    _mobile_attck_json="https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json"
    _nist_controls_json="https://raw.githubusercontent.com/center-for-threat-informed-defense/attack-control-framework-mappings/master/frameworks/nist800-53-r4/stix/nist800-53-r4-controls.json"
    _generated_attck_json="https://github.com/swimlane/pyattck/blob/master/generated_attck_data.json?raw=True"
    _generated_nist_json="https://github.com/swimlane/pyattck/blob/master/attck_to_nist_controls.json?raw=True"
    _requests_kwargs = {}
