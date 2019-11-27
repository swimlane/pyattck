import requests, yaml, base64
from github import Github

from githubcontroller import GitHubController
from attacktemplate import AttackTemplate


class AtomicRedTeam(GitHubController):

    __RAW_URL = 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/{}'
    __REPO = 'redcanaryco/atomic-red-team'

    def __init__(self):
        super(AtomicRedTeam, self).__init__()
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
                if file_content.path.endswith('yaml') and not file_content.path.endswith('index.yaml'):
                    if 'atomics/' in file_content.path:
                        content = self.__download_raw_content(self.__RAW_URL.format(file_content.path))
                        return_list.append(self.__parse_yaml_content(content, file_content.path))
        
        return return_list
                        
    def __parse_yaml_content(self, content, url):
        template = AttackTemplate()
       # print(content)
        for test in content['atomic_tests']:
            if 'executor' in test:
                if 'command' in test['executor']:
                    if 'input_arguments' in test:
                        self.temp_command_string = None
                        for key,val in test['input_arguments'].iteritems():
                            replacement_string = '#{{{0}}}'.format(key)
                            if self.temp_command_string is None:
                                try:
                                    self.temp_command_string = test['executor']['command'].replace(replacement_string, test['input_arguments'][key]['default'])
                                    template.add_command(url,self.temp_command_string)
                                except:
                                    pass
                            else:
                                try:
                                    self.temp_command_string = self.temp_command_string.replace(replacement_string, test['input_arguments'][key]['default'])
                                    template.add_command(url,self.temp_command_string)
                                except:
                                    pass
                                self.temp_command_string = None
                    else:
                        template.add_command(url,test['executor']['command'])
        template.id = content['attack_technique']
        template.add_dataset('Atomic Red Team Test - {name}'.format(name=content['display_name']), content)
        return template.get()      
        

    def __download_raw_content(self, url):
        response = self.session.get(url)
        if response.status_code == 200:
            return yaml.load(response.content, Loader=yaml.FullLoader)