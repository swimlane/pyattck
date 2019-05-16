import json 
from collections import OrderedDict

def jsonDefault(OrderedDict):
    return OrderedDict.__dict__

class AttckObject(object):
    """
        Parent class to all other classes
        Creates objects that are categorized as Mitre ATT&CK Groups (e.g. APT1, APT32, etc.)
    
        Arguments:
            AttckObject (dict) -- Takes the Mitre ATT&CK Json object as a kwargs values
    """
    
    def __init__(self, **kwargs):
        """Creates objects that are categorized as Mitre ATT&CK Groups (e.g. APT1, APT32, etc.)
        """
        self.id = self._set_id(kwargs)
        self.name = self._set_attribute(kwargs, 'name')
        self.alias = self._set_attribute(kwargs, 'aliases')
        self.description = self._set_attribute(kwargs, 'description')
        self.reference = self._set_reference(kwargs)
        self.created = self._set_attribute(kwargs, 'created')
        self.modified = self._set_attribute(kwargs, 'modified')
        self.stix = self._set_attribute(kwargs, 'id')
        self.type = self._set_attribute(kwargs, 'type')
        self.wiki = self._set_wiki(kwargs)
        self.contributor = self._set_attribute(kwargs, 'contributor')

    def __str__(self):
        return json.dumps(self, default=jsonDefault, indent=4)

    def set_relationship(self, obj, id, name):
        return_list = []
        for item in obj['objects']:
            if 'source_ref' in item:
                if id in item['source_ref']:
                    for o in obj['objects']:
                        if o['type'] == name:
                            if item['target_ref'] in o['id']:
                                return_list.append(o)
        return return_list

    def _set_attribute(self, obj, name):
        """Parent class method to set attribute based on passed in object
           and the name of the property
        
        Arguments:
            obj (dict) -- Provided json objects are passed to this method
            name (str) -- The json property name to set attribute in child classes
        
        Returns:
            (str) -- Returns either the value of the attribute requested or returns 'null'
        """
        try:
            return obj.get(name)
        except:
            return 'null'


    def _set_list_items(self, obj, list_name):
        item_value = []
        if list_name in obj:
            for item in obj[list_name]:
                item_value.append(item)
                
            return item_value

    def _set_id(self, obj):
        """Returns the Mitre ATT&CK Framework external ID 
        
        Arguments:
            obj (dict) -- A Mitre ATT&CK Framework json object
        
        Returns:
            (str) -- Returns the Mitre ATT&CK Framework external ID
        """
        if "external_references" in obj:
            for p in obj['external_references']:
                for s in p:
                    if p[s] == 'mitre-attack':
                        return p['external_id']        

    def _set_wiki(self, obj):
        """Returns the Mitre ATT&CK Framework Wiki URL
        
        Arguments:
            obj (dict) -- A Mitre ATT&CK Framework json object
        
        Returns:
            (str) -- Returns the Mitre ATT&CK Framework Wiki URL
        """
        if "external_references" in obj:
            for p in obj['external_references']:
                for s in p:
                    if p[s] == 'mitre-attack':
                        return p['url']


    def _set_reference(self, obj):
        """Returns a list of external references from the provided Mitre ATT&CK Framework json object
        
        Arguments:
            obj (dict) -- A Mitre ATT&CK Framework json object
        
        Returns:
            (dict) -- Returns a dict containing the following key/value pairs
                external_id (str) -- The Mitre ATT&CK Framework external ID
                url (str)         -- The Mitre ATT&CK Framework URL
                source_name (str) -- The Mitre ATT&CK Framework source name
                description (str) -- The Mitre ATT&CK Framework description or None if it does not exist
        """
        external_id = ''
        url = ''
        source_name = ''
        description = ''

        external_references = {}
        if "external_references" in obj:
            for p in obj['external_references']:
                if 'external_id' in p:
                    external_id = p['external_id']
                if 'url' in p:
                    url = p['url']
                if 'source_name' in p:
                    source_name = p['source_name']
                if 'description' in p:
                    description = p['description']
                else:
                    description = None

                external_references.update({
                    'external_id': external_id,
                    'url': url,
                    'source': source_name,
                    'description': description
                })
            return external_references