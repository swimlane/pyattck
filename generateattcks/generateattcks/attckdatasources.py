import requests
import yaml
from .githubcontroller import GitHubController
from .attacktemplate import AttackTemplate
from .base import Base


class AttckDatasources(GitHubController, Base):

    """
    Data Source: https://github.com/mitre-attack/attack-datasources
    Author: MITRE ATT&CK

    This class is a wrapper for the above data set
    """

    __RAW_URL = 'https://raw.githubusercontent.com/mitre-attack/attack-datasources/main/{}'
    __REPO = 'mitre-attack/attack-datasources'

    def __init__(self):
        super(AttckDatasources, self).__init__()
        self.session = requests.Session()
        self._dataset = []

    def get(self):
        repo = self.github.get_repo(self.__REPO)
        contents = repo.get_contents("")
        while contents:
            file_content = contents.pop(0)
            if file_content.type == "dir":
                contents.extend(repo.get_contents(file_content.path))
            else:
                if file_content.path.endswith('techniques_to_relationships_mapping.yaml'):
                    content = self.__download_raw_content(self.__RAW_URL.format(file_content.path))
                    return self.__parse_yaml_content(content, file_content.path)

    def __parse_yaml_content(self, content, url):
        return_list = []
        for item in content:
            template = AttackTemplate()
            template.id = item.get('technique_id')
            template.add_external_reference(item.get('references'))
            template.add_detection_data_sources({
                'data_source': item.get('data_source'),
                'defintion': item.get('defintion'),
                'collection_layers': item.get('collection_layers'),
                'data_source_platform': item.get('data_source_platform'),
                'data_component': item.get('data_component'),
                'description': item.get('description'),
                'source_data_element': item.get('source_data_element'),
                'relationship': item.get('relationship'),
                'target_data_element': item.get('target_data_element')
            })
            return_list.append(template.get())
        return return_list

    def __download_raw_content(self, url):
        response = self.session.get(url)
        if response.status_code == 200:
            return yaml.load(response.content, Loader=yaml.FullLoader)
