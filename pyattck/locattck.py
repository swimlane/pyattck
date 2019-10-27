import json
import os

from .pyattck import Attck
from .pyattck import __MITRE_ATTCK_JSON_URL__

EXCEPTION_LIST = (UnicodeDecodeError, TypeError)
try:
    EXCEPTION_LIST += (json.JSONDecodeError, )
except AttributeError:
    pass


class LocalAttck(Attck):
    def __init__(self, local_file_path=None):
        """
        Arguments:
            local_file_path (str) -- Path where json is placed, if is file it will loaded locally
        """
        load = True
        self.local_file_path = local_file_path
        if os.path.isfile(local_file_path):
            with open(local_file_path) as f:
                try:
                    self._attck = json.load(f)
                    load = False
                except EXCEPTION_LIST:
                    pass
        if load:
            self.attck = __MITRE_ATTCK_JSON_URL__
