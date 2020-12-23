class AttckControl:

    """An object that represents a compliance control type.

    Currently this object is only utilized by NIST 800-53 controls
    but will be expanded in the future.

    Each control relates to a technique and can assist with identifying
    compliance needs and coverage for specific techniques
    and sub-techniques.

    Example:
        You can iterate over an `techniques` list and access specific
        control properties.

            1. To iterate over an `techniques` list, do the following:

            .. code-block:: python

               from pyattck import Attck

               attck = Attck()

               for technique in attck.enterprise.techniques:
                   print(technique.id)
                   print(technique.name)
                   print(technique.alias)
                   print(technique.description)
                   # etc.
                   # you can access controls related to a technique
                   for control in technique.controls:
                       print(control.id)
                       print(control.name)
                       print(control.description)
                       # etc.

    Arguments:
        kwargs (dict) -- Takes the raw control Json object
    """

    def __init__(self, **kwargs):
        """
        This class represents a compliance Control as defined from
        external data sources.

        Keyword Arguments:
            kwargs (dict) -- A compliance control JSON object
        """
        self.id = self._set_id(kwargs.pop('external_references'))
        self.stix = kwargs.pop('id')
        for key,val in kwargs.items():
            prop_name = key.replace('x_mitre_','')
            if not hasattr(self, prop_name):
                setattr(self, prop_name, val)

    def __str__(self):
        """
        Returns dictionary string of all properties and
        values for the instance

        Returns:
            (str): All properties and values of instance
        """
        return_dict = {}
        for key,val in self.__dict__.items():
            if not key.startswith('_'):
                return_dict[key] = val
        return str(return_dict)

    def __repr__(self):
        """
        Returns a printable representation of an object

        Returns:
            str: Returns a printable representation of an object
        """
        return "{class_name}('{name}', '{id}')".format(
            class_name=self.__class__.__name__,
            name=self.name,
            id=self.id
        )

    def _set_id(self, external_references):
        """
        Returns the compliance control (external) ID

        Arguments:
            external_references (list) -- A list of external_references

        Returns:
            (str) -- Returns the compliance control (external) ID
        """
        for reference in external_references:
            if 'NIST' in reference.get('source_name'):
                return reference.get('external_id')
        return 'No ID Defined'
