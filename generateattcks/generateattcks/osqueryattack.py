import requests, re, yaml
try:
    from StringIO import StringIO ## for Python 2
except ImportError:
    from io import StringIO ## for Python 3

from .githubcontroller import GitHubController
from .attacktemplate import AttackTemplate
from .markdowntable import MarkdownTable
from .base import Base


class OsqueryAttack(GitHubController, Base):
    """
    Data Source: https://github.com/teoseller/osquery-attck
    Authors:
        - teoseller

    This class is a wrapper for the above data set
    """

    __URL = 'https://raw.githubusercontent.com/teoseller/osquery-attck/master/{}'
    
    __REPO = 'teoseller/osquery-attck'

    def __init__(self):
        super(OsqueryAttack, self).__init__()
        self.session = requests.Session()
        self._dataset = []
        self.__temp_attack_paths = []

    def get(self):
        return_list = []
        repo = self.github.get_repo(self.__REPO)
        contents = repo.get_contents("")
        while contents:
            file_content = contents.pop(0)
            if file_content.type == "dir":
                contents.extend(repo.get_contents(file_content.path))
            else:
                if file_content.path.endswith('conf'):
                    content = self.__download_raw_content(self.__URL.format(file_content.path))
                    return_list.append(content)
        return return_list

    def __download_raw_content(self, url):
        response = self.session.get(url)
        if response.status_code == 200:
            content = response.json()
            for key,val in content['queries'].items():
                temp = val['description'].split('ATT&CK ')
                if len(temp) <= 2:
                    template = AttackTemplate()
                    template.id = 'T1000'
                else:
                    technique_list = temp[1].split(',')
                    description = temp[0].replace('-','').strip()
                    for technique in technique_list:
                        template = AttackTemplate()
                        template.id = technique
                        for k,v in val.items():
                            if 'query' in k:
                                template.add_possible_queries('Osquery ATT&CK',v,name=description)
                            
        return template.get()