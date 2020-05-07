import requests, yaml, base64, re
from github import Github

from .githubcontroller import GitHubController
from .attacktemplate import AttackTemplate


class ElementalAttack(GitHubController):
    """
    Data Source: https://github.com/Elemental-attack/Elemental
    Author: 
        * Josh Hakala (<a href="https://github.com/exec-bypass">exec-bypass</a>)
        * Steve Rice (<a href="https://github.com/sdrice">sdrice</a>)
        * Aaron Crouch (<a href="https://github.com/TTwoONEsiXX">TTwoONEsiXX</a>)
        * Erick Pasco (<a href="https://github.com/epasco5">epasco5</a>)

    This class is a wrapper for the above data set
    """
    
    __RAW_URL = 'https://raw.githubusercontent.com/Elemental-attack/Elemental/master/{}'
    __REPO = 'Elemental-attack/Elemental'

    def __init__(self):
        super(ElementalAttack, self).__init__()
        self.session = requests.Session()
        self._dataset = []

    def get(self):
        return_list = []
        repo = self.github.get_repo(self.__REPO)
        contents = repo.get_contents("")
        while contents:
            file_content = contents.pop(0)
            if file_content.type == "dir":
                contents.extend(repo.get_contents(file_content.path))
            else:
                if file_content.path.endswith('yml'):
                    if 'sigma_rules/' in file_content.path:
                        content = self.__download_content(self.__RAW_URL.format(file_content.path))
                        return_list.append(self.__get_attack_template(content))
        return return_list


    def __get_attack_template(self, return_list):
        template = AttackTemplate()
        technique_id = None
        group_id = None
        for item in return_list:
            if 'tags' in item:
                for tag in item['tags']:
                    if '.' in tag:
                        if tag.split('.')[1].startswith('t'):
                            technique_id = tag.split('.')[1].upper()
                        if tag.split('.')[1].startswith('g'):
                            group_id = tag.split('.')[1].upper()
                template.id = technique_id
            if technique_id:
                template.add_detection_data_sources(item)
        return template.get()


    def __download_content(self, url):
        return_list = []
        response = self.session.get(url)
        if response.status_code == 200:
            content = response.text
            if content:
                if '---' in content:
                    content = content.split('---')
                    for item in content:
                        return_list.append(yaml.load(item, Loader=yaml.FullLoader))
                else:
                    return_list.append(yaml.load(content, Loader=yaml.FullLoader))
        return return_list