import json
import os
import warnings

import yaml
from attrs import asdict, define, field
from pydantic import DirectoryPath, FilePath, HttpUrl
from requests.api import request

from .utils.exceptions import UnknownFileError
from .utils.utils import get_absolute_path, is_path, is_url


@define
class Configuration:
    data_path: DirectoryPath = field(default="~/pyattck/data", converter=get_absolute_path)
    enterprise_attck_json: HttpUrl or FilePath = field(
        default="https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_enterprise_attck_v1.json",
        converter=get_absolute_path,
    )
    pre_attck_json: HttpUrl or FilePath = field(
        default="https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_pre_attck_v1.json",
        converter=get_absolute_path,
    )
    mobile_attck_json: HttpUrl or FilePath = field(
        default="https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_mobile_attck_v1.json",
        converter=get_absolute_path,
    )
    ics_attck_json: HttpUrl or FilePath = field(
        default="https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_ics_attck_v1.json",
        converter=get_absolute_path,
    )
    nist_controls_json: HttpUrl or FilePath = field(
        default="https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_nist_controls_v1.json",
        converter=get_absolute_path,
    )
    generated_nist_json: HttpUrl or FilePath = field(
        default="https://swimlane-pyattck.s3.us-west-2.amazonaws.com/attck_to_nist_controls.json",
        converter=get_absolute_path,
    )

    @enterprise_attck_json.validator
    @pre_attck_json.validator
    @mobile_attck_json.validator
    @ics_attck_json.validator
    @nist_controls_json.validator
    @generated_nist_json.validator
    def _validate_json_value(self, attribute, value):
        path_valid = False
        url_valid = False
        path_valid = is_path(value)
        url_valid = is_url(value)
        if not path_valid and not url_valid:
            raise Exception("The provided value is neither a URL or file path")


@define(frozen=True)
class Options:
    nested_techniques: bool = field(default=False)
    use_config: bool = field(default=False)
    save_config: bool = field(default=False)
    config_file_path: FilePath = field(default="~/pyattck/config.yml", converter=get_absolute_path)
    config: Configuration = field(factory=Configuration)
    kwargs: dict = field(factory=dict)

    def _download_url_data(self, url):
        response = request("GET", url, **self.kwargs)
        if response.status_code == 200:
            return response.json()
        return {}

    def _read_from_disk(self, path):
        if os.path.exists(path) and os.path.isfile(path):
            try:
                with open(path) as f:
                    if path.endswith(".json"):
                        return json.load(f)
                    elif path.endswith(".yml") or path.endswith(".yaml"):
                        return Configuration(**yaml.load(f, Loader=yaml.SafeLoader))
                    else:
                        raise UnknownFileError(provided_value=path, known_values=[".json", ".yml", ".yaml"])
            except Exception as e:
                warnings.warn(
                    message=f"The provided config file {path} is not in the correct format. "
                    "Using default values instead."
                )
                pass
        elif os.path.isdir(path):
            raise Exception(f"The provided path is a directory and must be a file: {path}")

    def _save_to_disk(self, path, data):
        try:
            if not os.path.exists(os.path.dirname(path)):
                try:
                    os.makedirs(os.path.dirname(path))
                except Exception as e:
                    raise Exception(
                        "pyattck attempted to create the provided directories but was unable to: {}".format(path)
                    )
            with open(path, "w+") as f:
                if path.endswith(".json"):
                    json.dump(data, f)
                elif path.endswith(".yml") or path.endswith(".yaml"):
                    yaml.dump(data, f)
                else:
                    raise UnknownFileError(provided_value=path, known_values=[".json", ".yml", ".yaml"])
        except IsADirectoryError as ie:
            raise Exception(f"The provided path is a directory: {path}")

    def _save_json_data(self, force: bool = False) -> None:
        if not os.path.exists(self.config.data_path):
            try:
                os.makedirs(self.config.data_path)
            except Exception as e:
                raise Exception("Unable to save data to the provided location: {}".format(self.config.data_path))
        for json_data in [
            "enterprise_attck_json",
            "pre_attck_json",
            "mobile_attck_json",
            "ics_attck_json",
            "nist_controls_json",
            "generated_nist_json",
        ]:
            if is_url(getattr(self.config, json_data)):
                try:
                    path = os.path.join(self.config.data_path, f"{json_data}.json")
                    if not os.path.exists(path) or force:
                        data = self._download_url_data(getattr(self.config, json_data))
                        self._save_to_disk(path, data)
                except Exception as e:
                    raise Warning(f"Unable to download data from {json_data}")
        return True

    def get_data(self, value: str) -> dict:
        """Retrieves saved data based on key value in config.

        Args:
            value (str): A key value in our configuration file.

        Returns:
            dict: The dictionary object which was retrieved.
        """
        data = getattr(self.config, value)
        if is_url(data):
            return self._download_url_data(data)
        else:
            return self._read_from_disk(getattr(self.config, value))

    def _save_config(self, config_file_path: str, config_dict: dict) -> None:
        """Saves the config to the provided path."""
        self._save_to_disk(config_file_path, config_dict)
        self._save_json_data()

    def __attrs_post_init__(self):
        """Contains options and configuration for pyattck."""
        if self.save_config:
            self._save_config(config_file_path=self.config_file_path, config_dict=asdict(self.config))
        if self.use_config:
            self._save_config(config_file_path=self.config_file_path, config_dict=asdict(self.config))
            object.__setattr__(self, "config", self._read_from_disk(self.config_file_path))
