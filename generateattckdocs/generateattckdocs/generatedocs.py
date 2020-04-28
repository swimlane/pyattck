from generateattackdocs.actordocs import ActorDocs
from generateattackdocs.techniquedocs import TechniqueDocs
from generateattackdocs.tooldocs import ToolDocs
from generateattackdocs.tacticdocs import TacticDocs
from generateattackdocs.malwaredocs import MalwareDocs
from generateattackdocs.mitigationdocs import MitigationDocs

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