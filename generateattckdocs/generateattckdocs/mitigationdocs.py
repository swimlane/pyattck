import os

from .attckdocs import AttckDocs


class MitigationDocs(AttckDocs):

    def __init__(self, folder):
        self.folder = os.path.abspath(folder)
        if not os.path.exists(self.folder):
            os.mkdir(self.folder)
        if not os.path.exists(os.path.join(self.folder, 'mitigations')):
            os.mkdir(os.path.join(self.folder, 'mitigations'))
        
        self.folder = os.path.join(self.folder, 'mitigations')
        

    def go(self):
        for mitigation in self._attck.enterprise.mitigations:
            markdown = None
            markdown = '''
# {name}

## Description

### MITRE Description

> {description}

'''.format(
    name=mitigation.name,
    description=mitigation.description,
)
            technique_list = None
            for technique in mitigation.techniques:
                if technique_list is None:
                    technique_list = '''
* [{name}](../techniques/{id}.md)
'''.format(name=technique.name, id=technique.name.replace(' ', '-').replace('/','-'))
                else:
                    technique_list += '''
* [{name}](../techniques/{id}.md)
    '''.format(name=technique.name, id=technique.name.replace(' ', '-').replace('/','-'))
            
            markdown += '''
# Techniques

{technique_list}
'''.format(technique_list=technique_list)

            with open('{folder}/{name}.md'.format(folder=self.folder, name=mitigation.name.replace(' ', '-').replace('/','-')), 'w+') as f:
                f.write(markdown)
