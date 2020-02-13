import requests, yaml

from .githubcontroller import GitHubController
from .attacktemplate import AttackTemplate


class BlueTeamLabs(GitHubController):
    """ Data Source: https://github.com/BlueTeamLabs/sentinel-attack
    Authors:
        - [Edoardo Gerosa](https://twitter.com/netevert)
        - [Olaf Hartong](https://twitter.com/olafhartong) 

    This class is a wrapper for the above data set
    """
    
    __URL = 'https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/{}'
    __REPO = 'BlueTeamLabs/sentinel-attack'

    def __init__(self):
        super(BlueTeamLabs, self).__init__()
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
                if file_content.path.endswith('txt'):
                    if 'detections/' in file_content.path:
                        template = AttackTemplate()
                        content = self.__download_raw_content(self.__URL.format(file_content.path))
                        file_name = file_content.path.rsplit('/', 1)[1]
                        template.id = file_name.split('_',1)[0]
                        query_name = file_name.rsplit('.txt')[0].replace(template.id,'').replace('_',' ').strip()
                        template.add_possible_queries('Azure Sentinel',content, name=query_name)
                        return_list.append(template.get())
        return return_list
           
    def __download_raw_content(self, url):
        response = self.session.get(url)
        if response.status_code == 200:
            lines = ''
            for line in response.text.splitlines():
                if not line.strip().startswith("//"):
                    lines += line
            return lines