from ..datasets import AttckDatasets
from ..utils.exceptions import GeneratedDatasetException


class AttckControl:
    '''
    An object that represents a compliance control type.
    Currently this object is only utilized by NIST 800-53 controls
    but will be expanded in the future.

    Each control relates to a technique and can assist with identifying
    compliance needs and coverage for specific techniques
    and sub-techniques.
    
    Each control gives you access to the following properties on the object:

        1. created - The created date of the object
        2. description - The description of the control
        3. external_references - 
        1. command_list - A list of commands associated with a technique
        2. commands = A list of dictionary objects containing source, command, and provided name associated with a technique
        3. queries = A list of dictionary objects containing product, query, and name associated with a technique
        4. datasets = A list of raw datasets associated with a technique
        5. possible_detections = A list of raw datasets containing possible detection methods for a technique


    Example:
        You can iterate over an `techniques` list and access specific control properties.

        
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
    '''

    def __init__(self, **kwargs):
        self.id = self._set_id(kwargs.pop('external_references'))
        self.stix = kwargs.pop('id')
        for key,val in kwargs.items():
            prop_name = key.replace('x_mitre_','')
            if not hasattr(self, prop_name):
                setattr(self, prop_name, val)

    def __str__(self):
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
        """Returns the compliance control (external) ID 
        
        Arguments:
            external_references (list) -- A list of external_references
        
        Returns:
            (str) -- Returns the compliance control (external) ID
        """
        for reference in external_references:
            if reference.get('source_name') == 'NIST 800-53 Revision 4':
                return reference.get('external_id')
        return 'No ID Defined'
