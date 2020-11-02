import os
from .actordocs import ActorDocs
from .techniquedocs import TechniqueDocs
from .tooldocs import ToolDocs
from .tacticdocs import TacticDocs
from .malwaredocs import MalwareDocs
from .mitigationdocs import MitigationDocs

class GenerateDocs(object):

    def __init__(self, folder):
        self.folder = folder

    def read_files(self, folder_name):
        return_list = []
        folder_path = os.path.abspath(os.path.join(self.folder, folder_name))
        for item in os.listdir(folder_path):
            return_list.append(item)
        sorted_list = []
        for item in sorted(return_list):
            sorted_list.append(f"* [{item.rsplit('.md')[0]}](/external-data/{folder_name}/{item})")
        return sorted_list

    def create_index(self, name, item_list):
        text = f'# {name.capitalize()}\n\n'
        for item in item_list:
            text += item + '\n'
        with open(name + '.md', 'w+') as file:
            file.write(text)

    def go(self):
        ActorDocs(self.folder).go()
        self.create_index('actors', self.read_files('actors'))
        TechniqueDocs(self.folder).go()
        self.create_index('techniques', self.read_files('techniques'))
        ToolDocs(self.folder).go()
        self.create_index('tools', self.read_files('tools'))
        TacticDocs(self.folder).go()
        self.create_index('tactics', self.read_files('tactics'))
        MalwareDocs(self.folder).go()
        self.create_index('malwares', self.read_files('malwares'))
        MitigationDocs(self.folder).go()
        self.create_index('mitigations', self.read_files('mitigations'))
       # with open('')