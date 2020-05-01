import csv

import requests

from .attacktemplate import AttackTemplate


class C2Matrix(object):
    """
    Data Source: https://www.thec2matrix.com/
    Authors:
        - [Jorge Orchilles](https://twitter.com/jorgeorchilles)
        - [Bryson Bort](https://twitter.com/brysonbort) 
        - [Adam Mashinchi](https://twitter.com/adam_mashinchi)

    This class is a wrapper for the above data set, which is focused on details surrounding different C2 (Command & Control) tools/software
    """

    _URL = 'https://docs.google.com/spreadsheet/ccc?key=1b4mUxa6cDQuTV2BPC6aA-GR4zGZi0ooPYtBe4IgPsSc&output=csv'
    OFFSET = 1

    def get(self):
        response = requests.get(self._URL)
        data = response.text
        return self._parse(data)
        
    def _parse(self, data):
        count = 0
        headers = None
        template = AttackTemplate()
        for item in csv.reader(data.splitlines()):
            count += 1
            if count == 1:
                continue
            if count == 2:
                headers = item
                continue
            c2_dict = dict(zip(headers, item))

            template.add_c2_data(c2_dict['Name'], c2_dict)
        return template.get()