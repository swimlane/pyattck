import requests, yaml, markdown

from bs4 import BeautifulSoup

from .githubcontroller import GitHubController
from .attacktemplate import AttackTemplate


class LitmusTest(GitHubController):
    """ Data Source: https://github.com/Kirtar22/Litmus_Test
    Authors:
        - Kirtar22

    This class is a wrapper for the above data set
    """
    
    __URL = 'https://raw.githubusercontent.com/Kirtar22/Litmus_Test/master/{}'
    __REPO = 'Kirtar22/Litmus_Test'

    def __init__(self):
        super(LitmusTest, self).__init__()
        self.md = markdown.Markdown()
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
                if file_content.path.endswith('.md') and file_content.path.split('/')[-1].startswith('T'):
                    content = self.__download_raw_content(file_content.download_url)
                    template = self.__parse_markdown(content)
                    if template:
                        return_list.append(template)
        return return_list


    def __parse_markdown(self, content):
        if content.strip():
            template = AttackTemplate()
            template_id = False
            commands = False
            data_sources = False
            queries = False
            for line in content.splitlines():
                line = str(line.decode('utf-8'))
                if template_id is False:
                    if line.startswith('# '):
                        if line.strip('# ').split('-')[0].startswith('T'):
                            template.id = line.strip('# ').split('-')[0].strip()
                            template_id = True
                if '## Simulating the attack' in line:
                    commands = True
                    continue
                if commands:
                    if line:
                        if not line.startswith('#'):
                            template.add_command(self.__REPO, line.strip())
                        elif line.startswith('#'):
                            commands = False
                if '## Data sources' in line:
                    data_sources = True
                    continue
                if data_sources:
                    if line:
                        if not line.startswith('#'):
                            template.add_detection_data_sources(line.strip())
                        elif line.startswith('#'):
                            data_sources = False
                if '## Splunk Queries' in line:
                    queries = True
                    continue
                if queries:
                    if line:
                        if line.startswith('###'):
                            continue
                        if not line.startswith('#'):
                            template.add_possible_queries('Splunk',line.strip())
                        elif line.startswith('#'):
                            queries = False
            return template.get()
        
        
    def __download_raw_content(self, url):
        response = self.session.get(url)
        if response.status_code == 200:
            return response.content