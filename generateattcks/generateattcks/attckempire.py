import requests, xlrd
from io import BytesIO
from zipfile import ZipFile

from .attacktemplate import AttackTemplate


class AttckEmpire(object):
    """
    Data Source: https://github.com/dstepanic/attck_empire
    Author: dstepanic

    This class is a wrapper for the above data set, which is focused on detection of 
    specific Empire modules related to ATT&CK Techniques.
    """

    URL = 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'

    OFFSET = 1
    
    def _parse(self, sheet):
        header_row = sheet.row(0)

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
        return rows

    def __format(self, data):
        return_list = []
        for item in data:
            template = AttackTemplate()
            if 'ATT&CK Technique #1' in item:
                template.id = item['ATT&CK Technique #1']
                if 'Empire Module' in item:
                    template.add_command(self.URL, item['Empire Module'], name='Empire Module Command')
            if 'ATT&CK Technique #2' in item:
                template.id = item['ATT&CK Technique #1']
                if 'Empire Module' in item:
                    template.add_command(self.URL, item['Empire Module'], name='Empire Module Command')
                
            template.add_dataset('Empire Module XLSX Sheet by dstepanic', item)
            return_list.append(template.get())
        return return_list

    def get(self):
        response = requests.get(self.URL)
        workbook = xlrd.open_workbook(file_contents=response.content)  # open workbook
        worksheet = workbook.sheet_by_index(0)  # get first sheet
        parsed_data = self._parse(worksheet)
        return self.__format(parsed_data)
