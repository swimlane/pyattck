import requests, re, yaml
try:
    from StringIO import StringIO ## for Python 2
except ImportError:
    from io import StringIO ## for Python 3

from .githubcontroller import GitHubController
from .attacktemplate import AttackTemplate
from .markdowntable import MarkdownTable


class AtomicThreatCoverage(GitHubController):
    """
    Data Source: https://github.com/atc-project/atomic-threat-coverage
    Authors:
        - Daniil Yugoslavskiy, [@yugoslavskiy](https://github.com/yugoslavskiy)
        - Jakob Weinzettl, [@mrblacyk](https://github.com/mrblacyk)
        - Mateusz Wydra, [@sn0w0tter](https://github.com/sn0w0tter)
        - Mikhail Aksenov, [@AverageS](https://github.com/AverageS)

    This class is a wrapper for the above data set
    """
    
    __URL = 'https://raw.githubusercontent.com/atc-project/atomic-threat-coverage/master/{}'
    __REPO = 'atc-project/atomic-threat-coverage'

    def __init__(self):
        super(AtomicThreatCoverage, self).__init__()
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
                if file_content.path.endswith('md'):
                    if 'Atomic_Threat_Coverage/Detection_Rules/' in file_content.path:
                        content = None
                        try:
                            content = self.__download_raw_content(self.__URL.format(file_content.path))
                        except:
                            pass
                        if content:
                            return_list.append(content.get())
        return return_list

    def __download_raw_content(self, url):
        response = self.session.get(url)
        if response.status_code == 200:
            regexp = re.compile(r"((.*\n){2})```([^`]*)```")
            found = re.findall(regexp, response.content)
            template = AttackTemplate()
            for item in found:
                if isinstance(item, tuple):
                    name = None
                    content = None
                    for match in item:
                        stripped_match = match.rstrip('\r\n')
                        if stripped_match:
                            if name is None:
                                if stripped_match.startswith('#'):
                                    name = stripped_match.replace('#','').strip()
                            elif content is None and stripped_match.rstrip('\r\n').strip():
                                content = stripped_match.strip()
                                if 'Sigma' in name and content:
                                    if '---' in content:
                                        content = content.split('---')[0]
                                    yml = yaml.load(content, Loader=yaml.FullLoader)
                                    if 'tags' in yml:
                                        for t in yml['tags']:
                                            if len(t.split('.')) >= 2:
                                                if t.split('.')[1].startswith('t'):
                                                    template = AttackTemplate()
                                                    template.id = t.split('.')[1].upper()
                                                    template.add_possible_queries('Atomic Threat Coverage', content, name=name)
                                    else:
                                        template.id = 'T0000'
                                template.add_possible_queries('Atomic Threat Coverage', content, name=name)
                                name = None
                                content = None
        if getattr(template, 'id', None):
            return template
        else:
            template.id = 'T0000'
            return template