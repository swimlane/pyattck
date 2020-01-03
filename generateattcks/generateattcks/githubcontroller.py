import yaml, os
from github import Github


class GitHubController(object):

    def __init__(self):
        token = self.__get_token_from_env_variable()
        self.github = Github(token)

    def __get_token_from_env_variable(self):
        return os.environ['GH_TOKEN']

    def __get_token_from_config(self):
        cfg = ''
        with open("./config.yml", 'r') as ymlfile:
            cfg = yaml.load(ymlfile)
        if 'GitHub' in cfg:
            if 'token' in cfg['GitHub']:
                return cfg['GitHub']['token']
