import os, json

import pprint

from .attckdocs import AttckDocs


class TechniqueDocs(AttckDocs):

    def __init__(self, folder):
        self.folder = os.path.abspath(folder)
        if not os.path.exists(self.folder):
            os.mkdir(self.folder)
        if not os.path.exists(os.path.join(self.folder, 'techniques')):
            os.mkdir(os.path.join(self.folder, 'techniques'))
        
        self.folder = os.path.join(self.folder, 'techniques')
        

    def go(self):
        for technique in self._attck.enterprise.techniques:
            markdown = None
            alias = None
            command_list = None
            if hasattr(technique, 'alias'):
                if technique.alias:
                    alias = technique.alias
            if hasattr(technique, 'command_list'):
                if technique.command_list:
                    command_list = technique.command_list
            commands = None
            if hasattr(technique, 'commands'):
                if technique.commands:
                    if isinstance(technique.commands, list):
                        commands = pprint.pformat(technique.commands)
                    else:
                        commands = technique.commands
            possible_detections = None
            if hasattr(technique, 'possible_detections'):
                if technique.possible_detections:
                    if isinstance(technique.possible_detections, list):
                        possible_detections = pprint.pformat(technique.possible_detections)
                    else:
                        possible_detections = technique.possible_detections
            queries = None
            if hasattr(technique, 'queries'):
                if technique.queries:
                    if isinstance(technique.queries, list):
                        queries = pprint.pformat(technique.queries)
                    else:
                        queries = technique.queries
            datasets = None
            if hasattr(technique, 'datasets'):
                if technique.datasets:
                    if isinstance(technique.datasets, list):
                        datasets = pprint.pformat(technique.datasets)
                    else:
                        datasets = technique.datasets
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

* Bypass: {bypass}
* Effective Permissions: {effective_permissions}
* Network: {network}
* Permissions: {permissions}
* Platforms: {platforms}
* Remote: {remote}
* Type: {type}
* Wiki: {wiki}

## Potential Commands

```
{command_list}
```

## Commands Dataset

```
{commands}
```

## Potential Detections

```json
{possible_detections}
```

## Potential Queries

```json
{queries}
```

## Raw Dataset

```json
{datasets}
```
'''.format(
    name=technique.name,
    description=technique.description,
    alias='' if not alias else '\n'.join([str(x) for x in alias]),
    bypass=technique.bypass,
    effective_permissions=technique.effective_permissions,
    network=technique.network,
    permissions=technique.permissions,
    platforms=technique.platforms,
    remote=technique.remote,
    type=technique.type,
    wiki=technique.wiki,
    command_list='' if not command_list else '\n'.join([str(x) for x in command_list]),
    commands='' if not commands else commands,
    possible_detections='' if not possible_detections else possible_detections,
    queries='' if not queries else queries,
    datasets='' if not datasets else datasets
)

            tactic_list = None
            for tactic in technique.tactics:
                if tactic_list is None:
                    tactic_list = '''
* [{name}](../tactics/{id}.md)
'''.format(name=tactic.name, id=tactic.name.replace(' ', '-').replace('/','-'))
                else:
                    tactic_list += '''
* [{name}](../tactics/{id}.md)
    '''.format(name=tactic.name, id=tactic.name.replace(' ', '-').replace('/','-'))
    
            markdown += '''
# Tactics

{tactic_list}
'''.format(tactic_list=tactic_list)


            mitigation_list = None
            for mitigation in technique.mitigations:
                if mitigation_list is None:
                    mitigation_list = '''
* [{name}](../mitigations/{id}.md)
'''.format(name=mitigation.name, id=mitigation.name.replace(' ', '-').replace('/','-'))
                else:
                    mitigation_list += '''
* [{name}](../mitigations/{id}.md)
    '''.format(name=mitigation.name, id=mitigation.name.replace(' ', '-').replace('/','-'))
    
            markdown += '''
# Mitigations

{mitigation_list}
'''.format(mitigation_list=mitigation_list)



            actors_list = None
            for actor in technique.actors:
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

            technique_name = technique.name.replace(' ', '-').replace('/','-')
            with open('{folder}/{name}.md'.format(folder=self.folder, name=technique_name), 'w+') as f:
                f.write(markdown)
