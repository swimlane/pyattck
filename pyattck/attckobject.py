import json


def json_default(obj):
    return obj.__dict__


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
        self._obj = kwargs
        self._reference = []
        self.load()

        self.reference = self._get_reference()
        self.id = self._get_id()
        self.name = self._get_attribute('name')
        self.alias = self._get_attribute('aliases')
        self.description = self._get_attribute('description')
        self.created = self._get_attribute('created')
        self.modified = self._get_attribute('modified')
        self.stix = self._get_attribute('id')
        self.type = self._get_attribute('type')
        self.wiki = self._get_wiki()
        self.contributor = self._get_attribute('contributor')

    def __str__(self):
        return json.dumps(self, default=json_default, indent=4)

    def load(self):
        self._reference = []
        if "external_references" in self._obj:
            for p in self._obj['external_references']:
                self._reference.append({
                    'external_id': p.get('external_id', ''),
                    'url': p.get('url', ''),
                    'source': p.get('source_name', ''),
                    'description': p.get('description', ''),
                    'mitre-attack': p.get('mitre-attack', ''),
                })

    def _get_attribute(self, name):
        """Parent class method to set attribute based on passed in object
           and the name of the property
        
        Arguments:
            obj (dict) -- Provided json objects are passed to this method
            name (str) -- The json property name to set attribute in child classes
        
        Returns:
            (str) -- Returns either the value of the attribute requested or returns 'null'
        """
        return self._obj.get(name, 'null')

    def _get_list_items(self, list_name):
        items = self._obj.get(list_name, None)
        if not isinstance(items, (list, tuple)):
            items = [items]
        return items

    def _get_id(self):
        """Returns the Mitre ATT&CK Framework external ID 
        
        Arguments:
            obj (dict) -- A Mitre ATT&CK Framework json object
        
        Returns:
            (str) -- Returns the Mitre ATT&CK Framework external ID
        """
        for p in self._reference:
            if p['mitre-attack']:
                return p['external_id']
        return str(id(self))

    def _get_wiki(self):
        """Returns the Mitre ATT&CK Framework Wiki URL
        
        Arguments:
            obj (dict) -- A Mitre ATT&CK Framework json object
        
        Returns:
            (str) -- Returns the Mitre ATT&CK Framework Wiki URL
        """
        for p in self._reference:
            if p['mitre-attack']:
                return p['url']

    def _get_reference(self):
        """Returns a list of external references from the provided Mitre ATT&CK Framework json object
        
        Arguments:
            obj (dict) -- A Mitre ATT&CK Framework json object
        
        Returns:
            (dict) -- Returns a list of dict containing the following key/value pairs
                external_id (str) -- The Mitre ATT&CK Framework external ID
                url (str)         -- The Mitre ATT&CK Framework URL
                source_name (str) -- The Mitre ATT&CK Framework source name
                description (str) -- The Mitre ATT&CK Framework description or None if it does not exist
        """
        return self._reference
