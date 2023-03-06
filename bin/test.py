from pyattck import Attck

attack = Attck(nested_techniques=False, save_config=True)

# Examples of MITRE Enterprise ATT&CK using nested subtechniques

for relationship in attack.enterprise.relationships:
    print(relationship.id)
    print(relationship.description)

for actor in attack.enterprise.actors:
    print(actor.id)
    print(actor.name)

    # accessing malware used by an actor or group
    for malware in actor.malwares:
        print(malware.id)
        print(malware.name)

    # accessing tools used by an actor or group
    for tool in actor.tools:
        print(tool.id)
        print(tool.name)

    # accessing techniques used by an actor or group
    for technique in actor.techniques:
        print(technique.id)
        print(technique.name)
        print(technique.data_sources)
        # you can also access generated data sets on aa technique
        print(technique.command_list)
        print(technique.commands)
        print(technique.queries)
        print(technique.datasets)
        print(technique.possible_detections)
        # You can access subtechniques nested under techniques by default
        for subtechnique in technique.subtechniques:
            print(subtechnique.id)
            print(subtechnique.name)
            # etc.
        # To access all techniques under a single technique object set
        # Attck(nested_subtechniques=False)

        # to get a count of controls for a technique do the following
        print(len(technique.controls))

        # below will print each controls properties & values
        for control in technique.controls:
            print(control.__dict__)
        
        # below will print the id, name and description of a control
        for control in technique.controls:
            print(control.id)
            print(control.name)
            print(control.description)

# accessing data_sources
for data_source in attack.enterprise.data_sources:
    print(data_source.name)
    print(data_source.id)
    for technique in data_source.techniques:
        print(technique.id)
        print(technique.name)
    for component in data_source.data_components:
        print(component.name)
        print(component.id)

# accessing malware
for malware in attack.enterprise.malwares:
    print(malware.id)
    print(malware.name)

    # accessing actor or groups using this malware
    for actor in malware.actors:
        print(actor.id)
        print(actor.name)

    # accessing techniques that this malware is used in
    for technique in malware.techniques:
        print(technique.id)
        print(technique.name)

        # to get a count of controls for a technique do the following
        print(len(technique.controls))

        # below will print each controls properties & values
        for control in technique.controls:
            print(control.__dict__)
        
        # below will print the id, name and description of a control
        for control in technique.controls:
            print(control.id)
            print(control.name)
            print(control.description)

# accessing mitigation
for mitigation in attack.enterprise.mitigations:
    print(mitigation.id)
    print(mitigation.name)

    # accessing techniques related to mitigation recommendations
    for technique in mitigation.techniques:
        print(technique.id)
        print(technique.name)
        # you can also access generated data sets on aa technique
        print(technique.command_list)
        print(technique.commands)
        print(technique.queries)
        print(technique.datasets)
        print(technique.possible_detections)
    
        # to get a count of controls for a technique do the following
        print(len(technique.controls))

        # below will print each controls properties & values
        for control in technique.controls:
            print(control.__dict__)
        
        # below will print the id, name and description of a control
        for control in technique.controls:
            print(control.id)
            print(control.name)
            print(control.description)

# accessing tactics
for tactic in attack.enterprise.tactics:
    print(tactic.id)
    print(tactic.name)

    # accessing techniques related to this tactic
    for technique in tactic.techniques:
        print(technique.id)
        print(technique.name)
        # you can also access generated data sets on aa technique
        print(technique.command_list)
        print(technique.commands)
        print(technique.queries)
        print(technique.datasets)
        print(technique.possible_detections)
    
        # to get a count of controls for a technique do the following
        print(len(technique.controls))

        # below will print each controls properties & values
        for control in technique.controls:
            print(control.__dict__)
        
        # below will print the id, name and description of a control
        for control in technique.controls:
            print(control.id)
            print(control.name)
            print(control.description)

for technique in attack.enterprise.techniques:
    print(technique.id)
    print(technique.stix)
    print(technique.name)

    # to get a count of controls for a technique do the following
    print(len(technique.controls))

    # below will print each controls properties & values
    for control in technique.controls:
        print(control.__dict__)
    
    # below will print the id, name and description of a control
    for control in technique.controls:
        print(control.id)
        print(control.name)
        print(control.description)

    # you can also access generated data sets on aa technique
    print(technique.command_list)
    print(technique.commands)
    print(technique.queries)
    print(technique.datasets)
    print(technique.possible_detections)

    # Access all subtechnique objects
    print(technique.subtechniques)

    # iterate through subtechniques
    for subtechnique in technique.subtechniques:
        print(subtechnique.name)
        print(subtechnique.id)

    # accessing data_sources that this technique has
    for data_source in technique.data_sources:
        print(data_source.id)
        print(data_source.name)

    # accessing tactics that this technique belongs to
    for tactic in technique.tactics:
        print(tactic.id)
        print(tactic.name)

    # accessing mitigation recommendations for this technique
    for mitigation in technique.mitigations:
        print(mitigation.id)
        print(mitigation.name)

    # accessing actors using this technique
    for actor in technique.actors:
        print(actor.id)
        print(actor.name)

# accessing tools
for tool in attack.enterprise.tools:
    print(tool.id)
    print(tool.name)

    # accessing techniques this tool is used in
    for technique in tool.techniques:
        print(technique.id)
        print(technique.name)
        # you can also access generated data sets on aa technique
        print(technique.command_list)
        print(technique.commands)
        print(technique.queries)
        print(technique.datasets)
        print(technique.possible_detections)

    # accessing actor or groups using this tool
    for actor in tool.actors:
        print(actor.id)
        print(actor.name)

# Examples of MITRE PRE-ATT&CK 

for actor in attack.preattack.actors:
    print(actor.id)
    print(actor.name)

    # accessing techniques used by an actor or group
    for technique in actor.techniques:
        print(technique.id)
        print(technique.name)

# accessing tactics
for tactic in attack.preattack.tactics:
    print(tactic.id)
    print(tactic.name)

    # accessing techniques related to this tactic
    for technique in tactic.techniques:
        print(technique.id)
        print(technique.name)


# accessing techniques
for technique in attack.preattack.techniques:
    print(technique.id)
    print(technique.name)

    # accessing tactics that this technique belongs to
    for tactic in technique.tactics:
        print(tactic.id)
        print(tactic.name)

    # accessing actors using this technique
    for actor in technique.actors:
        print(actor.id)
        print(actor.name)

# Examples of MITRE Mobile ATT&CK

for actor in attack.mobile.actors:
    print(actor.id)
    print(actor.name)

    # accessing malware used by an actor or group
    for malware in actor.malwares:
        print(malware.id)
        print(malware.name)

    # accessing tools used by an actor or group
    for tool in actor.tools:
        print(tool.id)
        print(tool.name)

    # accessing techniques used by an actor or group
    for technique in actor.techniques:
        print(technique.id)
        print(technique.name)
        # you can also access generated data sets on aa technique
        print(technique.command_list)
        print(technique.commands)
        print(technique.queries)
        print(technique.datasets)
        print(technique.possible_detections)

# accessing malware
for malware in attack.mobile.malwares:
    print(malware.id)
    print(malware.name)

    # accessing actor or groups using this malware
    for actor in malware.actors:
        print(actor.id)
        print(actor.name)

    # accessing techniques that this malware is used in
    for technique in malware.techniques:
        print(technique.id)
        print(technique.name)

# accessing mitigation
for mitigation in attack.mobile.mitigations:
    print(mitigation.id)
    print(mitigation.name)

    # accessing techniques related to mitigation recommendations
    for technique in mitigation.techniques:
        print(technique.id)
        print(technique.name)
        # you can also access generated data sets on aa technique
        print(technique.command_list)
        print(technique.commands)
        print(technique.queries)
        print(technique.datasets)
        print(technique.possible_detections)

# accessing tactics
for tactic in attack.mobile.tactics:
    print(tactic.id)
    print(tactic.name)

    # accessing techniques related to this tactic
    for technique in tactic.techniques:
        print(technique.id)
        print(technique.name)
        # you can also access generated data sets on aa technique
        print(technique.command_list)
        print(technique.commands)
        print(technique.queries)
        print(technique.datasets)
        print(technique.possible_detections)

# accessing techniques
for technique in attack.mobile.techniques:
    print(technique.id)
    print(technique.name)
    # you can also access generated data sets on aa technique
    print(technique.command_list)
    print(technique.commands)
    print(technique.queries)
    print(technique.datasets)
    print(technique.possible_detections)

    # accessing tactics that this technique belongs to
    for tactic in technique.tactics:
        print(tactic.id)
        print(tactic.name)

    # accessing mitigation recommendations for this technique
    for mitigation in technique.mitigations:
        print(mitigation.id)
        print(mitigation.name)

    # accessing actors using this technique
    for actor in technique.actors:
        print(actor.id)
        print(actor.name)

# accessing tools
for tool in attack.mobile.tools:
    print(tool.id)
    print(tool.name)

    # accessing techniques this tool is used in
    for technique in tool.techniques:
        print(technique.id)
        print(technique.name)
        # you can also access generated data sets on aa technique
        print(technique.command_list)
        print(technique.commands)
        print(technique.queries)
        print(technique.datasets)
        print(technique.possible_detections)

    # accessing actor or groups using this tool
    for actor in tool.actors:
        print(actor.id)
        print(actor.name)


# Accessing ICS MITRE ATT&CK Framework

# accessing data_sources
for data_source in attack.ics.data_sources:
    print(data_source.name)
    print(data_source.id)
    for technique in data_source.techniques:
        print(technique.id)
        print(technique.name)
    for component in data_source.data_components:
        print(component.name)
        print(component.id)

# accessing malware
for malware in attack.ics.malwares:
    print(malware.id)
    print(malware.name)

    # accessing techniques that this malware is used in
    for technique in malware.techniques:
        print(technique.id)
        print(technique.name)

        # to get a count of controls for a technique do the following
        print(len(technique.controls))

        # below will print each controls properties & values
        for control in technique.controls:
            print(control.__dict__)
        
        # below will print the id, name and description of a control
        for control in technique.controls:
            print(control.id)
            print(control.name)
            print(control.description)

# accessing mitigation
for mitigation in attack.ics.mitigations:
    print(mitigation.id)
    print(mitigation.name)

    # accessing techniques related to mitigation recommendations
    for technique in mitigation.techniques:
        print(technique.id)
        print(technique.name)
        # you can also access generated data sets on aa technique
        print(technique.command_list)
        print(technique.commands)
        print(technique.queries)
        print(technique.datasets)
        print(technique.possible_detections)
    
        # to get a count of controls for a technique do the following
        print(len(technique.controls))

        # below will print each controls properties & values
        for control in technique.controls:
            print(control.__dict__)
        
        # below will print the id, name and description of a control
        for control in technique.controls:
            print(control.id)
            print(control.name)
            print(control.description)

# accessing tactics
for tactic in attack.ics.tactics:
    print(tactic.id)
    print(tactic.name)

    # accessing techniques related to this tactic
    for technique in tactic.techniques:
        print(technique.id)
        print(technique.name)
        # you can also access generated data sets on aa technique
        print(technique.command_list)
        print(technique.commands)
        print(technique.queries)
        print(technique.datasets)
        print(technique.possible_detections)
    
        # to get a count of controls for a technique do the following
        print(len(technique.controls))

        # below will print each controls properties & values
        for control in technique.controls:
            print(control.__dict__)
        
        # below will print the id, name and description of a control
        for control in technique.controls:
            print(control.id)
            print(control.name)
            print(control.description)

for technique in attack.ics.techniques:
    print(technique.id)
    print(technique.stix)
    print(technique.name)

    # to get a count of controls for a technique do the following
    print(len(technique.controls))

    # below will print each controls properties & values
    for control in technique.controls:
        print(control.__dict__)
    
    # below will print the id, name and description of a control
    for control in technique.controls:
        print(control.id)
        print(control.name)
        print(control.description)

    # you can also access generated data sets on aa technique
    print(technique.command_list)
    print(technique.commands)
    print(technique.queries)
    print(technique.datasets)
    print(technique.possible_detections)

    # accessing data_sources that this technique has
    for data_source in technique.data_sources:
        print(data_source)
        print(data_source.id)
        print(data_source.name)

    # accessing tactics that this technique belongs to
    for tactic in technique.tactics:
        print(tactic.id)
        print(tactic.name)

    # accessing mitigation recommendations for this technique
    for mitigation in technique.mitigations:
        print(mitigation.id)
        print(mitigation.name)
