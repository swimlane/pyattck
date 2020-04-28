import os


from generateattackdocs.attckdocs import AttckDocs


class TacticDocs(AttckDocs):

    def __init__(self, folder):
        self.folder = os.path.abspath(folder)
        if not os.path.exists(self.folder):
            os.mkdir(self.folder)
        if not os.path.exists(os.path.join(self.folder, 'tactics')):
            os.mkdir(os.path.join(self.folder, 'tactics'))
        
        self.folder = os.path.join(self.folder, 'tactics')
        

    def go(self):
        for tactic in self._attck.enterprise.tactics:
            markdown = None
            markdown = '''
# {name}

> {short_name}

## Description

### MITRE Description

> {description}

'''.format(
    name=tactic.name,
    short_name=tactic.short_name,
    description=tactic.description
)
            technique_list = None
            for technique in tactic.techniques:
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

            with open('{folder}/{name}.md'.format(folder=self.folder, name=tactic.name.replace(' ', '-').replace('/','-')), 'w+') as f:
                f.write(markdown)
