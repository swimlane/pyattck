import requests, yaml, base64

from .githubcontroller import GitHubController
from .attacktemplate import AttackTemplate


class MitreStockpile(GitHubController):
    """
    Data Source: https://github.com/mitre/stockpile
    Authors:
        - Mitre

    This class is a wrapper for the above data set
    """
    
    __RAW_URL = 'https://raw.githubusercontent.com/mitre/stockpile/master/{}'
    __REPO = 'mitre/stockpile'

    def __init__(self):
        super(MitreStockpile, self).__init__()
        self.session = requests.Session()
        self._dataset = []
        self.__temp_attack_paths = []

    @property
    def stockpile(self):
        return self.__stockpile

    @stockpile.setter
    def stockpile(self, val):
        self.__stockpile = val

    @property
    def attack_paths(self):
        return self.__attack_paths

    @attack_paths.setter
    def attack_paths(self, val):
        self.__attack_paths = val


    def get_stockpile(self):
        return self.__stockpile

    def get_attack_paths(self):
        return self.__attack_paths

    def run(self):
        return_list = []
        repo = self.github.get_repo(self.__REPO)
        contents = repo.get_contents("")
        while contents:
            file_content = contents.pop(0)
            if file_content.type == "dir":
                contents.extend(repo.get_contents(file_content.path))
            else:
                if file_content.path.endswith('yml') and not file_content.path.endswith('index.yaml'):
                    if 'data/adversaries' in file_content.path:
                        content = self.__download_raw_content(self.__RAW_URL.format(file_content.path))
                        parsed_yaml = self.__parse_yaml_content(content, file_content.path)
                        if parsed_yaml:
                            return_list.append(parsed_yaml)
                    if 'data/abilities' in file_content.path:
                        content = self.__download_raw_content(self.__RAW_URL.format(file_content.path))
                        parsed_yaml = self.__parse_yaml_content(content, file_content.path)
                        if parsed_yaml:
                            return_list.append(parsed_yaml)
        self.stockpile = return_list

        return_list = []
        for content in self.stockpile:
            if content:
                for path in self.__temp_attack_paths:
                    for item in content['parsed_datasets']:
                        for k,v in item.items():
                            for key,val in path['phases'].items():
                                if isinstance(val, list):
                                    for i in val:
                                        if v['id'] == i:
                                            path['phases'][key].append({
                                                'technique_id': v['technique']['attack_id'],
                                                'name': v['name'],
                                                'description': v['description']
                                            })
                                            path['phases'][key].remove(i)
                    return_list.append(path)
        
        self.attack_paths = return_list

    def gen_dict_extract(self, key, var):
        if hasattr(var,'items'):
            for k, v in var.items():
                if k == key:
                    yield v
                if isinstance(v, dict):
                    for result in self.gen_dict_extract(key, v):
                        yield result
                elif isinstance(v, list):
                    for d in v:
                        for result in self.gen_dict_extract(key, d):
                            yield result
                        
    def __parse_yaml_content(self, content, url):
        if isinstance(content, list):
            template = AttackTemplate()
            for item in content:
                template.id = item['technique']['attack_id']
                if item.get('platforms'):
                    if isinstance(item['platforms'], dict):
                        new_item = self.gen_dict_extract('command', item)
                        if new_item:
                            for command in new_item:
                                template.add_command(url, command, name=item['description'])
                    else:
                        template.add_command(url,item['platforms'], name=item['description'])
                template.add_dataset('Mitre Stockpile - {}'.format(item['description']),item)
            return template.get()
        else:
            if content:
                if 'phases' in content:
                    self.__temp_attack_paths.append(content)

    def __download_raw_content(self, url):
        response = self.session.get(url)
        if response.status_code == 200:
            return yaml.load(response.content, Loader=yaml.FullLoader)