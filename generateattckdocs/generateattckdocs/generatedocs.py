from .actordocs import ActorDocs
from .techniquedocs import TechniqueDocs
from .tooldocs import ToolDocs
from .tacticdocs import TacticDocs
from .malwaredocs import MalwareDocs
from .mitigationdocs import MitigationDocs

class GenerateDocs(object):

    def __init__(self, folder):
        self.folder = folder

    def go(self):
        ActorDocs(self.folder).go()
        TechniqueDocs(self.folder).go()
        ToolDocs(self.folder).go()
        TacticDocs(self.folder).go()
        MalwareDocs(self.folder).go()
        MitigationDocs(self.folder).go()