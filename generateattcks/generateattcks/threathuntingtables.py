import requests, csv

from .attacktemplate import AttackTemplate
from .base import Base


class ThreatHuntingTables(Base):
    """
    Data Source: https://github.com/dwestgard/threat_hunting_tables

    Authors:
        - dwestgard

    This class is a wrapper for the above data set
    """

    __URL = 'https://raw.githubusercontent.com/dwestgard/threat_hunting_tables/master/process_chains.csv'

    def __get_csv_data(self):
        return_list = []
        response = requests.get(self.__URL)
        decoded_content = response.content.decode('utf-8')
        cr = csv.reader(decoded_content.splitlines(), delimiter=',')
        my_list = list(cr)
        headers = my_list[0]
        for row in my_list:
            return_list.append(dict(zip(headers, row)))
        return return_list

    def int_or_float(self, strg):
        val = float(strg)
        return int(val) if val.is_integer() else val

    def get(self):
        return_list = []
        for item in self.__get_csv_data():
            if item['mitre_attack'].startswith('T'):
                template = AttackTemplate()
                template.id = item['mitre_attack']
                if item['parent_process']:
                    if item['commandline_string']:
                        template.add_command('Threat Hunting Tables','{} {}'.format(item['parent_process'], item['commandline_string']))
                    else:
                        template.add_command('Threat Hunting Tables',item['parent_process'], name='parent_process')
                if item['file_path']:
                    template.add_command('Threat Hunting Tables',item['file_path'], name='file_path')
                if item['registry_path']:
                    template.add_command('Threat Hunting Tables',item['registry_path'],name='registry_path')
                if item['registry_value']:
                    template.add_command('Threat Hunting Tables',item['registry_value'], name='registry_value')
                
                if item['loaded_dll']:
                    template.add_command('Threat Hunting Tables',item['loaded_dll'], name='loaded_dll')
                if item['sub_process_1']:
                    template.add_command('Threat Hunting Tables',item['sub_process_1'], name='sub_process_1')
                if item['sub_process_2']:
                    template.add_command('Threat Hunting Tables',item['sub_process_2'], name='sub_process_2')

                template.add_dataset('Threat Hunting Tables', item)
                return_list.append(template.get())
        return return_list