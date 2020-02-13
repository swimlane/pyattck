import requests, yaml

from .attacktemplate import AttackTemplate


class SysmonHunter(object):
    """
    Data Source: https://github.com/baronpan/SysmonHunter
    Authors:
        - baronpan

    This class is a wrapper for the above data set
    """
    
    __URL = 'https://raw.githubusercontent.com/baronpan/SysmonHunter/master/misc/attck.yaml'

    def __get_data(self):
        response = requests.get(self.__URL)
        return yaml.load(response.content, Loader=yaml.FullLoader)

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

    def get(self):
        return_list = []
        for key,val in self.__get_data().items():
            template = AttackTemplate()
            template.id = key
            for item in val['query']:
                command_name = ''.join(self.gen_dict_extract('pattern', item))
                template.add_command('SysmonHunter - {}'.format(val['name']), command_name)
            template.add_dataset('SysmonHunter - {}'.format(key), val)
            return_list.append(template.get())
        return return_list