
from .attckobject import AttckObject

class AttckActor(AttckObject):
    """A child class of AttckObject
       Creates objects that are categorized as Mitre ATT&CK Actors or Groups (e.g. APT1, APT32, etc.)
    
    Arguments:
        attck_obj (json) -- Takes the raw Mitre ATT&CK Json object
        AttckObject (dict) -- Takes the Mitre ATT&CK Json object as a kwargs values
    """

    def __init__(self, attck_obj = None, **kwargs):

        self.attck_obj = attck_obj

        self.id = super(AttckActor, self)._set_id(kwargs)
        self.created_by_ref = super(AttckActor, self)._set_attribute(kwargs, 'created_by_ref')
        self.revoked = super(AttckActor, self)._set_attribute(kwargs, 'revoked')
        self.name = super(AttckActor, self)._set_attribute(kwargs, 'name')
        self.aliases = super(AttckActor, self)._set_list_items(kwargs, 'aliases')
        self.description = super(AttckActor, self)._set_attribute(kwargs, 'description')
        self.external_reference = super(AttckActor, self)._set_reference(kwargs)
        self.created = super(AttckActor, self)._set_attribute(kwargs, 'created')
        self.modified = super(AttckActor, self)._set_attribute(kwargs, 'modified')
        self.stix = super(AttckActor, self)._set_attribute(kwargs, 'id')
        self.type = super(AttckActor, self)._set_attribute(kwargs, 'type')
        self.wiki = super(AttckActor, self)._set_wiki(kwargs)
        self.contributor = super(AttckActor, self)._set_list_items(kwargs, 'x_mitre_contributors')

    @property
    def malware(self):
        '''Returns all malware objects as a list that are documented as being used by an Actor or Group
        '''
        from malware import AttckMalware
        malware_list = []
        for item in self.attck_obj['objects']:
            if 'source_ref' in item:
                if self.stix in item['source_ref']:
                    for o in self.attck_obj['objects']:
                        if o['type'] == 'malware':
                            if item['target_ref'] in o['id']:
                                malware_list.append(AttckMalware(**o))
        return malware_list

    @property
    def tools(self):
        '''Returns all tool object as a list that are documented as being used by an Actor or Group'''
        from tools import AttckTools
        tools_list = []
        for item in self.attck_obj['objects']:
            if 'source_ref' in item:
                if self.stix in item['source_ref']:
                    for o in self.attck_obj['objects']:
                        if o['type'] == 'tool':
                            if item['target_ref'] in o['id']:
                                tools_list.append(AttckTools(**o))
        return tools_list

    @property
    def techniques(self):
        '''Returns all technique objects as a list that are documented as being used by an Actor or Group'''
        from technique import AttckTechnique
        technique_list = []
        for item in self.attck_obj['objects']:
            if 'source_ref' in item:
                if self.stix in item['source_ref']:
                    for o in self.attck_obj['objects']:
                        if o['type'] == 'attack-pattern':
                            if item['target_ref'] in o['id']:
                                technique_list.append(AttckTechnique(**o))
        return technique_list