import os
import json
import warnings
from pathlib import Path
from urllib.parse import urlparse
import attr
import yaml
from requests.api import request
from .utils.exceptions import UknownFileError


@attr.s(frozen=True)
class Configuration:

    use_config            = attr.ib(default=False, type=bool)
    save_config           = attr.ib(default=False, type=bool)
    config_file_path      = attr.ib(default='~/pyattck/config.yml', type=str)
    data_path             = attr.ib(default='~/pyattck/data', type=str)
    enterprise_attck_json = attr.ib(default="https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json", type=str)
    pre_attck_json        = attr.ib(default="https://raw.githubusercontent.com/mitre/cti/master/pre-attack/pre-attack.json", type=str)
    mobile_attck_json     = attr.ib(default="https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json", type=str)
    nist_controls_json    = attr.ib(default="https://raw.githubusercontent.com/center-for-threat-informed-defense/attack-control-framework-mappings/master/frameworks/nist800-53-r4/stix/nist800-53-r4-controls.json", type=str)
    generated_attck_json  = attr.ib(default="https://github.com/swimlane/pyattck/blob/master/generated_attck_data.json?raw=True", type=str)
    generated_nist_json   = attr.ib(default="https://github.com/swimlane/pyattck/blob/master/attck_to_nist_controls.json?raw=True", type=str)
    requests_kwargs       = attr.ib(default={})

    @config_file_path.validator
    def validate_config_file_path(cls, attribute, value):
        print(value)
        if value.endswith('.json') or value.endswith('.yml') or value.endswith('.yaml'):# or not cls.__check_if_path(value):
            pass
        else:
            raise ValueError('Please provide a config_file_path with .json, .yml, or .yaml extension.')

    @data_path.validator
    def validate_data_path(cls, attribute, value):
        if not cls.__check_if_path(value):
            raise ValueError('Please provide a directory for data_path value.')

    @enterprise_attck_json.validator
    @pre_attck_json.validator
    @mobile_attck_json.validator
    @nist_controls_json.validator
    @generated_attck_json.validator
    @generated_nist_json.validator
    def validate_path_or_url(cls, attribute, value):
        if not cls.__check_if_url(value) or not cls.__check_if_path(value):
            raise ValueError('Please provide a URl or path string as a value for any json files.')

    def __check_if_path(cls, value):
        if Path(value):
            return True
        return False

    def __check_if_url(cls, value):
        try:
            if urlparse(value).scheme in ['http', 'https']:
                return True
            return False
        except:
            return False

    def __attrs_post_init__(self):
        if self.save_config:
            print(self)
            print(attr.asdict(self))
            self.__save_config(self.config_file_path, self)

    def __save_config(cls, path, data):
        # save configuration to disk
        if not os.path.exists(os.path.dirname(path)):
            try:
                os.makedirs(os.path.dirname(path))
            except:
                raise Exception('pyattck attempted to create the provided directories but was unable to: {}'.format(path))
        with open(path, 'w+') as f:
            if path.endswith('.json'):
                json.dump(data, f)
            elif path.endswith('.yml') or path.endswith('.yaml'):
                yaml.dump(data, f)
            else:
                raise UknownFileError(provided_value=path, known_values=['.json', '.yml', '.yaml'])


    def _save_json_data(cls, force: bool=False) -> None:
        if not os.path.exists(cls.data_path):
            try:
                os.makedirs(cls.data_path)
            except:
                raise Exception(
                    'Unable to save data to the provided location: {}'.format(cls.data_path)
                )
        for json_data in ['enterprise_attck_json', 'pre_attck_json', 
                          'mobile_attck_json', 'nist_controls_json', 
                          'generated_attck_json', 'generated_nist_json']:
            if cls._check_if_url(getattr(cls, json_data)):
                path = os.path.join(cls.data_path, "{json_data}.json".format(json_data=json_data))
                if not os.path.exists(path) or force:
                    data = cls.__download_url_data(getattr(cls, json_data))
                    cls.__write_to_disk(path, data)
                setattr(cls, '_' + json_data, path)
        cls.__update_config()
