import requests, xlrd
from io import BytesIO
from zipfile import ZipFile

from .attacktemplate import AttackTemplate


class AdversaryEmulation(object):
    """
    Data Source: https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx
    Author: Mitre

    This class is a wrapper for the above data set
    """

    URL = 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'

    OFFSET = 2
    
    def _parse(self, sheet):
        header_row = sheet.row(1)

        columns = []
        for item in header_row:
            columns.append(str(item).split(':')[1].replace("'","").lstrip('u'))
    
        rows = []
        for i, row in enumerate(range(sheet.nrows)):
            if i <= self.OFFSET:
                continue
            r = []
            for j, col in enumerate(range(sheet.ncols)):
                r.append(sheet.cell_value(i, j))
            rows.append(dict(zip(columns, r)))

        for item in rows:
            new_dict = {}
            if item['Category']:
                techniques = [s.strip() for s in item['Category'].splitlines()]

                if len(techniques) > 1:
                    for tech in techniques:
                        new_dict = {}
                        new_dict['Category'] = tech
                        for key, val in item.items():
                            if 'Category' != key:
                                new_dict[key] = val
                        
                        rows.append(new_dict)
                    rows.remove(item)
        return rows


    def __format(self, data):
        return_list = []
        for item in data:
            template = AttackTemplate()
            template.id = item['Category']
            if item['Built-in Windows Command']:
                template.add_command(self.URL, item['Built-in Windows Command'],name='Built-in Windows Command')
            if item['Cobalt Strike']:
                template.add_command(self.URL, item['Cobalt Strike'],name='Cobalt Strike')
            if item['Metasploit']:
                template.add_command(self.URL, item['Metasploit'],name='Metasploit')
                
            template.add_dataset('Mitre APT3 Adversary Emulation Field Manual', item)
            return_list.append(template.get())
        return return_list

    def get(self):
        response = requests.get(self.URL)
        workbook = xlrd.open_workbook(file_contents=response.content)  # open workbook
        worksheet = workbook.sheet_by_index(0)  # get first sheet
        parsed_data = self._parse(worksheet)
        return self.__format(parsed_data)