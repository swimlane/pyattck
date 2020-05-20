

class MobileAttckObject(object):
    '''Parent class of all other MITRE Mobile ATT&CK based classes

    This is a private class and should not be accessed directly
    
    Arguments:
        AttckObject (dict) -- Takes the MITRE Mobile ATT&CK Json object as a kwargs values
    '''

    _RELATIONSHIPS = None
    
    def __init__(self, **kwargs):
        """
        Sets standard properties that are found in all child classes as well as provides standard methods used by inherited classes
        
        Arguments:
            kwargs (dict) -- Takes the MITRE Mobile ATT&CK Json object as a kwargs values
        """
        self.id = self._set_id(kwargs)
        self.name = self._set_attribute(kwargs, 'name')
        self.alias = self.__set_alias(kwargs)
        self.description = self._set_attribute(kwargs, 'description')
        self.reference = self._set_reference(kwargs)
        self.created = self._set_attribute(kwargs, 'created')
        self.modified = self._set_attribute(kwargs, 'modified')
        self.stix = self._set_attribute(kwargs, 'id')
        self.type = self._set_attribute(kwargs, 'type')
        

    def __str__(self):
        return_dict = {}
        for key,val in self.__dict__.items():
            if not key.startswith('_'):
                return_dict[key] = val
        return str(return_dict)

    def set_relationships(self, attck_obj):
        """Generates relationships within attck_obj based on a defined relationship from MITRE ATT&CK
        
        Args:
            attck_obj (dict): MITRE ATT&CK Json object
        """
        if not MobileAttckObject._RELATIONSHIPS:
            relationship_obj = {}
            for item in attck_obj['objects']:
                if 'type' in item:
                    if item['type'] == 'relationship':
                        source_id = item['source_ref']
                        target_id = item['target_ref']
                        if source_id not in relationship_obj:
                            relationship_obj[source_id] = []
                        relationship_obj[source_id].append(target_id)

                        if target_id not in relationship_obj:
                            relationship_obj[target_id] = []
                        relationship_obj[target_id].append(source_id)
            MobileAttckObject._RELATIONSHIPS = relationship_obj

    def __set_alias(self, obj):
        """Returns the Mitre ATT&CK Framework aliases
        
        Arguments:
            obj (dict) -- A Mitre ATT&CK Framework json object
        
        Returns:
            (str) -- Returns the Mitre ATT&CK Framework aliases
        """
        return_list = []
        if obj.get('aliases'):
            for item in obj['aliases']:
                return_list.append(item)
        if obj.get('x_mitre_aliases'):
            for item in obj['x_mitre_aliases']:
                return_list.append(item)
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
            value = obj.get(name)
            return None if not value else value
        except:
            return None


    def _set_list_items(self, obj, list_name):
        """Private method used by child classes and normalizes list items
        
        Args:
            obj (dict) -- Provided json objects are passed to this method
            list_name (str) -- The json property name to set list items attribute in child classes
        
        Returns:
            list: returns a list of values from the provided list_name property
        """        
        item_value = []
        if list_name in obj:
            for item in obj[list_name]:
                item_value.append(item)
            return item_value

    def _set_id(self, obj):
        """Returns the MITRE Mobile ATT&CK Framework external ID 
        
        Arguments:
            obj (dict) -- A MITRE Mobile ATT&CK Framework json object
        
        Returns:
            (str) -- Returns the MITRE Mobile ATT&CK Framework external ID
        """
        if obj.get('external_references'):
            for p in obj['external_references']:
                if p.get('source_name') == 'mitre-mobile-attack' or p.get('source_name') == 'mitre-attack':
                    return p.get('external_id')
        
    def _set_wiki(self, obj):
        """Returns the MITRE Mobile ATT&CK Framework Wiki URL
        
        Arguments:
            obj (dict) -- A MITRE Mobile ATT&CK Framework json object
        
        Returns:
            (str) -- Returns the MITRE Mobile ATT&CK Framework Wiki URL
        """
        if obj.get('external_references'):
            for p in obj['external_references']:
                if p.get('source_name') == 'mitre-mobile-attack' or p.get('source_name') == 'mitre-attack':
                    return p.get('url')


    def _set_reference(self, obj):
        """Returns a list of external references from the provided MITRE Mobile ATT&CK Framework json object
        
        Arguments:
            obj (dict) -- A MITRE Mobile ATT&CK Framework json object
        
        Returns:
            (dict) -- Returns a dict containing the following key/value pairs
                external_id (str) -- The MITRE Mobile ATT&CK Framework external ID
                url (str)         -- The MITRE Mobile ATT&CK Framework URL
                source_name (str) -- The MITRE Mobile ATT&CK Framework source name
                description (str) -- The MITRE Mobile ATT&CK Framework description or None if it does not exist
        """
        return_list = []
        if obj.get('external_references'):
            for p in obj['external_references']:
                return_list.append(p)
        return return_list
