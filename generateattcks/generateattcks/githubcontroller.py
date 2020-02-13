import yaml, os
from github import Github


class GitHubController(object):

    def __init__(self):
        token = self.__get_token_from_env_variable()
        if not token:
            token = self.__get_token_from_config()
        self.github = Github(token)

    def __get_token_from_env_variable(self):
        if 'GH_TOKEN' in os.environ:
            return os.environ['GH_TOKEN']
        return None

    def __get_token_from_config(self):
        cfg = ''
        with open("./config.yml", 'r') as ymlfile:
            cfg = yaml.load(ymlfile, Loader=yaml.FullLoader)
        if 'GitHub' in cfg:
            if 'token' in cfg['GitHub']:
                return cfg['GitHub']['token']
