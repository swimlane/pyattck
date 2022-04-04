from .attckobject import AttckObject


class AttckControl(AttckObject):

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

               for technique in attck.ics.techniques:
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

    def __init__(self, attck_obj = None, _enterprise_attck_obj=None, **kwargs):
        """
        This class represents a compliance Control as defined from
        external data sources.

        Keyword Arguments:
            kwargs (dict) -- A compliance control JSON object
        """
        super(AttckControl, self).__init__(**kwargs)
        self.__attck_obj = attck_obj
        self.__enterprise_attck_obj = _enterprise_attck_obj
        for key,val in kwargs.items():
            prop_name = key.replace('x_mitre_','')
            if not hasattr(self, prop_name):
                setattr(self, prop_name, val)

    @property
    def techniques(self):
        """
        Returns all technique objects as a list that are
        associated with a Tactic

        Returns:
            [list] -- A list of related technique objects defined
                      within the ICS MITRE ATT&CK Framework
        """
        from .technique import AttckTechnique
        technique_list = []
        for key,val in AttckObject.generated_nist_json.items():
            if self.stix in val:
                for item in self.__attck_obj['objects']:
                    if 'type' in item and item['type'] == 'attack-pattern' and key == item['id']:
                        technique_list.append(AttckTechnique(attck_obj=self.__attck_obj, _enterprise_attck_obj=self.__enterprise_attck_obj, **item))
        return technique_list
