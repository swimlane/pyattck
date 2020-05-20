import os

from .attckdocs import AttckDocs


class ActorDocs(AttckDocs):

    def __init__(self, folder):
        self.folder = os.path.abspath(folder)
        if not os.path.exists(self.folder):
            os.mkdir(self.folder)
        if not os.path.exists(os.path.join(self.folder, 'actors')):
            os.mkdir(os.path.join(self.folder, 'actors'))
        
        self.folder = os.path.join(self.folder, 'actors')
        

    def go(self):
        for actor in self._attck.enterprise.actors:
            markdown = None
            alias = None
            if hasattr(actor, 'alias'):
                if actor.alias:
                    alias = actor.alias
            markdown = '''
# {name}

```
{logo}
```

## Description

### MITRE Description

> {description}

### External Description

> {external_description}

## Aliases

```
{alias}
```

## Known Tools

```
{known_tools}
```

## Operations

```
{operations}
```

## Targets

```
{targets}
```

## Attribution Links

```
{attribution_links}
```

## Country

```
{country}
```

## Comments

```
{additional_comments}
```
'''.format(
    name=actor.name,
    logo=actor.ascii_logo,
    description=actor.description,
    external_description='' if not hasattr(actor, 'external_description') else '\n'.join([str(x) for x in actor.external_description]),
    alias='' if not alias else '\n'.join([str(x) for x in alias]),
    known_tools='' if not hasattr(actor, 'known_tools') else '\n'.join([str(x) for x in actor.known_tools]),
    operations='' if not hasattr(actor, 'operations') else '\n'.join([str(x) for x in actor.operations]),
    targets='' if not hasattr(actor, 'targets') else '\n'.join([str(x) for x in actor.targets]),
    attribution_links='' if not hasattr(actor, 'attribution_links') else '\n'.join([str(x) for x in actor.attribution_links]),
    country='' if not hasattr(actor, 'country') else '\n'.join([str(x) for x in actor.country]),
    additional_comments='' if not hasattr(actor, 'additional_comments') else '\n'.join([str(x) for x in actor.additional_comments])
)
            technique_list = None
            for technique in actor.techniques:
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



            malware_list = None
            for malware in actor.malwares:
                if malware_list is None:
                    malware_list = '''
* [{name}](../malwares/{id}.md)
'''.format(name=malware.name, id=malware.name.replace(' ', '-').replace('/','-'))
                else:
                    malware_list += '''
* [{name}](../malwares/{id}.md)
    '''.format(name=malware.name, id=malware.name.replace(' ', '-').replace('/','-'))
            
            markdown += '''
# Malwares

{malware_list}
'''.format(malware_list=malware_list)


            tools_list = None
            for tool in actor.tools:
                if tools_list is None:
                    tools_list = '''
* [{name}](../tools/{id}.md)
'''.format(name=tool.name, id=tool.name.replace(' ', '-').replace('/','-'))
                else:
                    tools_list += '''
* [{name}](../tools/{id}.md)
    '''.format(name=tool.name, id=tool.name.replace(' ', '-').replace('/','-'))
            
            markdown += '''
# Tools

{tools_list}
'''.format(tools_list=tools_list)

            with open('{folder}/{name}.md'.format(folder=self.folder, name=actor.name.replace(' ', '-').replace('/','-')), 'w+') as f:
                f.write(markdown)
