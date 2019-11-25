import markdown, codecs, re
from bs4 import BeautifulSoup
import collections


class MarkdownTable(object):

    def __init__(self, file_path=None, raw_content=None):
        if raw_content:
            self.input_file = raw_content
        else:
            try:
                self.input_file = (codecs.open(file_path, mode="r", encoding="utf-8")).read()
            except:
                raise AssertionError('Unable to open the provided file path')

        self.row_list = []
        self.column_list = self.columns()
        self.column_dict = collections.OrderedDict()
    

    def columns(self):
        column_list = []
        for line in re.findall("\\|[^\n]+\\|\n", self.input_file):
            if line: # TODO: Add logic to determine if this is the true header row
                result = [x.strip() for x in line.split('|')]
                for column in result:
                    if column:
                        column_list.append(column)
            return column_list
            
    def rows(self):
        row_count = 0
        return_list = []
        for line in re.findall("\\|[^\n]+\\|\n", self.input_file):
            if line and row_count >= 2: # TODO: Add logic to determine if this is the true header row
                return_dict = collections.OrderedDict()
                column_count = len(self.column_list)
                result = [x.strip() for x in line.split('|')]
                count = 0
                for column in result:
                    if column:
                        if count < column_count:
                            return_dict.update({
                                self.column_list[count]: column
                            })
                            count += 1
                return_list.append(return_dict)
            row_count += 1
        return return_list