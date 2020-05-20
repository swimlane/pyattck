import os, json

from .attckdocs import AttckDocs


class ToolDocs(AttckDocs):

    c2_attribute_list = [
        'HTTP',
        'Implementation',
        'Custom Profile',
        'DomainFront',
        'Multi-User',
        'SMB',
        'Kill Date',
        'macOS',
        'GitHub',
        'Key Exchange',
        'Chaining',
        'Price',
        'TCP',
        'Proxy Aware',
        'HTTP3',
        'HTTP2',
        'Date',
        'Evaluator',
        'Working Hours',
        'Slack',
        'FTP',
        'Version Reviewed',
        'Logging',
        'Name',
        'License',
        'Windows',
        'Stego',
        'Notes',
        'Server',
        'Actively Maint.',
        'Dashboard',
        'DNS',
        'Popular Site',
        'ICMP',
        'IMAP',
        'DoH',
        'Jitter',
        'How-To',
        'ATT&CK Mapping',
        'Kali',
        'Twitter',
        'MAPI',
        'Site',
        'Agent',
        'API',
        'UI',
        'Linux'
    ]

    def __init__(self, folder):
        self.folder = os.path.abspath(folder)
        if not os.path.exists(self.folder):
            os.mkdir(self.folder)
        if not os.path.exists(os.path.join(self.folder, 'tools')):
            os.mkdir(os.path.join(self.folder, 'tools'))
        
        self.folder = os.path.join(self.folder, 'tools')
        

    def add_c2_markdown_attributes(self, object, name):
        property_val = None
        property_list_val = None
        for attribute in self.c2_attribute_list:
            if hasattr(object, '{}'.format(attribute)):
                if getattr(object, '{}'.format(attribute), None):
                    if not property_list_val:
                        property_list_val = '''
* {prop_name}: {prop_val}
'''.format(prop_name=attribute, prop_val=getattr(object, '{}'.format(attribute)))
                    else:
                        property_list_val += '''
* {prop_name}: {prop_val}
'''.format(prop_name=attribute, prop_val=getattr(object, '{}'.format(attribute)))
        
        if property_list_val:
            property_val = '''
# {name}

{property_list_val} 
'''.format(name=name, property_list_val=property_list_val)
        return property_val

    def add_markdown_section(self, object, name, attribute_name):
        property_val = None
        if hasattr(object, '{}'.format(attribute_name)):
            if getattr(object, '{}'.format(attribute_name), None):
                property_val = '''

# {name}

```
{val}
```
'''.format(name=name, val='\n'.join([str(x) for x in getattr(object, '{}'.format(attribute_name))]))
        return property_val

    def go(self):
        for tool in self._attck.enterprise.tools:
            markdown = None
            command_list = None
    
            additional_names = self.add_markdown_section(tool, 'Additional Names', 'additional_names')
            attribution_links = self.add_markdown_section(tool, 'Attribution Links', 'attribution_links')
            family = self.add_markdown_section(tool, 'Family', 'family')
            additional_comments = self.add_markdown_section(tool, 'Additional Comments', 'additional_comments')
            c2_data = None
            c2_properties = None
            alias = None
            if hasattr(tool, 'alias'):
                if tool.alias:
                    alias = tool.alias
            if hasattr(tool, 'c2_data'):
                if getattr(tool, 'c2_data', None):
                    c2_data = json.dumps(tool.c2_data)
                    c2_properties = self.add_c2_markdown_attributes(tool,'C2 Matrix Properties')
   
            markdown = '''
# {name}

## Description

### MITRE Description

> {description}

## Aliases

```
{alias}
```

## Additional Attributes

* Type: {type}
* Wiki: {wiki}
'''.format(
    name=tool.name,
    description=tool.description,
    alias='' if not alias else '\n'.join([str(x) for x in alias]),
    type=tool.type,
    wiki=tool.wiki
)
            if c2_data:
                markdown += '''
# C2 Matrix Dataset

```json
{c2_data}
```
'''.format(c2_data=c2_data)
            if c2_properties:
                markdown += c2_properties
            if additional_names:
                markdown += additional_names
            if attribution_links:
                markdown += attribution_links
            if additional_comments:
                markdown += additional_comments
            if family:
                markdown += family


            technique_List = None
            for technique in tool.techniques:
                if technique_List is None:
                    technique_List = '''
* [{name}](../techniques/{id}.md)
'''.format(name=technique.name, id=technique.name.replace(' ', '-').replace('/','-'))
                else:
                    technique_List += '''
* [{name}](../techniques/{id}.md)
    '''.format(name=technique.name, id=technique.name.replace(' ', '-').replace('/','-'))
    
            markdown += '''
# Techniques

{technique_List}
'''.format(technique_List=technique_List)


            actors_list = None
            for actor in tool.actors:
                if actors_list is None:
                    actors_list = '''
* [{name}](../actors/{id}.md)
'''.format(name=actor.name, id=actor.name.replace(' ', '-').replace('/','-'))
                else:
                    actors_list += '''
* [{name}](../actors/{id}.md)
    '''.format(name=actor.name, id=actor.name.replace(' ', '-').replace('/','-'))
    
            markdown += '''
# Actors

{actors_list}
'''.format(actors_list=actors_list)

            tool_name = tool.name.replace(' ', '-').replace('/','-')
            with open('{folder}/{name}.md'.format(folder=self.folder, name=tool_name), 'w+') as f:
                f.write(markdown)