from .technique import AttckTechnique
from .malware import AttckMalware
from .mitigation import AttckMitigation
from .tactic import AttckTactic
from .control import AttckControl
from .datasource import AttckDataSource
from ..configuration import Configuration


class ICSAttck(object):

    """An interface to the ICS MITRE ATT&CK Framework.

    This class creates an interface to all data points in the
    MITRE ATT&CK ICS framework.

    This interface enables you to retrieve all properties within
    each item in the MITRE ATT&CK ICS Framework.

    The following categorical items can be accessed using this class:

        1. Tactics (Tactics are the phases defined by MITRE ATT&CK)
        2. Techniques (Techniques are the individual actions which can
           accomplish a tactic)
        3. Mitigations (Mitigations are recommendations to prevent or
           protect against a technique)
        4. Malwares (Malwares are specific pieces of malware used by actors
           (or in general) to accomplish a technique)

    You can also search the external dataset for external commands that are
    similar using the `search_commands` method.

        .. code-block:: python

            from pyattck import Attck

            attck = Attck()

            for search in attck.enterprise.search_commands('powershell'):
                print(search['technique'])
                print(search['reason_for_match'])

    Additionally, as of pyattck 2.0.0 you can now access additional datasets
    related to a technique. These datasets are
    [documented here](https://github.com/swimlane/pyattck/blob/master/generateattcks/README.md).

    Each technique enables you to access the following properties on the object:

        1. command_list - A list of commands associated with a technique
        2. commands = A list of dictionary objects containing source, command,
                      and provided name associated with a technique
        3. queries = A list of dictionary objects containing product, query, and
                     name associated with a technique
        4. datasets = A list of raw datasets associated with a technique
        5. possible_detections = A list of raw datasets containing possible detection
                                 methods for a technique

    As of pyattck 3.0 you can now access defined Compliance Controls related
    to a technique.

    Here is an example of retrieving a list of compliance controls:

        .. code-block:: python

            from pyattck import Attck

            attck = Attck()

            for technique in attck.ics.techniques:
                print(technique.id)
                print(technique.name)
                print(technique.description)

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

    Example:
        Once an Attck object is instantiated, you can access each object type as
        a list of objects (e.g. techniques, tactics, actors, etc.)

        You can iterate over each object list and access specific properties and
        relationship properties of each.

        The following relationship properties are accessible:
            1. Malwares
                1. Actor or Group(s) using this malware
                2. Techniques this malware is used with
            2. Mitigations
                1. Techniques related to a specific set of mitigation suggestions
            3. Tactics
                1. Techniques found in a specific Tactic (phase)
            4. Techniques
                1. Tactics a technique is found in
                2. Mitigation suggestions for a given technique
                3. Actor or Group(s) identified as using this technique

            1. To iterate over a list, do the following:

            .. code-block:: python

               from pyattck import Attck

               attck = Attck()

               for technique in attck.ics.techniques:
                   print(technique.id)
                   print(technique.name)
                   print(technique.description)
                   # etc.

               for mitigation in attck.ics.mitigations:
                   print(mitigation.id)
                   print(mitigation.name)
                   print(mitigation.description)
                   # etc.

            2. To access relationship properties, do the following:

            .. code-block:: python

               from pyattck import Attck

               attck = Attck()

               for technique in attck.ics.techniques:
                   print(technique.id)
                   print(technique.name)
                   print(technique.description)
                   # etc.

                   for actor in technique.actors:
                       print(actor.id)
                       print(actor.name)
                       print(actor.description)
                       # etc.

               for mitigation in attck.ics.mitigations:
                   print(mitigation.id)
                   print(mitigation.name)
                   print(mitigation.description)
                   # etc.

                   for technique in mitigation.techniques:
                       print(technique.name)
                       print(technique.description)
                       # etc.

    Arguments:
        attck_json (json) - The attck_json is supplied by the attck.py module
        when instantiated.

    Returns:
        [Attck]: Returns a Attck object that contains all data from the
                 MITRE ATT&CK Framework
    """

    __tactics = []
    __techniques = []
    __mitigations = []
    __malwares = []
    __controls = []
    __data_sources = []
    __ENTERPRISE_GENERATED_DATA_JSON = None
    __nist_controls_json = Configuration.get_data('nist_controls_json')
    __attck = Configuration.get_data('ics_attck_json')
    __enterprise_attck = Configuration.get_data('enterprise_attck_json')

    @property
    def controls(self):
        """
        Creates AttckControls objects

        Returns:
            (AttckControl) -- Returns a list of AttckControl objects
        """
        if not self.__controls:
            if self.__nist_controls_json.get('objects'):
                for control in self.__nist_controls_json['objects']:
                    if control.get('type') == 'course-of-action':
                        self.__controls.append(AttckControl(attck_obj=self.__attck, _enterprise_attck_obj=self.__enterprise_attck, **control))
        return self.__controls

    @property
    def data_sources(self):
        """
        Creates AttckDataSource objects

        Returns:
            (AttckDataSource) -- Returns a list of AttckDataSource objects
        """
        if not self.__data_sources:
            for source in self.__enterprise_attck['objects']:
                if source['type'] == 'x-mitre-data-source':
                    self.__data_sources.append(AttckDataSource(attck_obj=self.__enterprise_attck, _ics_attck_obj=self.__attck, **source))
        return self.__data_sources

    @property
    def tactics(self):
        """
        Creates AttckTactic objects

        Returns:
            (AttckTactic) -- (Returns a list of AttckTactic objects)
        """
        if not self.__tactics:
            for tactic in self.__attck['objects']:
                if tactic['type'] == 'x-mitre-tactic':
                    self.__tactics.append(AttckTactic(attck_obj=self.__attck, _enterprise_attck_obj=self.__enterprise_attck, **tactic))
        return self.__tactics

    @property
    def mitigations(self):
        """
        Creates AttckMitigation objects

        Returns:
            (AttckMitigation) -- (Returns a list of AttckMitigation objects)
        """
        if not self.__mitigations:
            for mitigation in self.__attck['objects']:
                if mitigation['type'] == 'course-of-action':
                    self.__mitigations.append(AttckMitigation(attck_obj=self.__attck, _enterprise_attck_obj=self.__enterprise_attck, **mitigation))
        return self.__mitigations

    @property
    def malwares(self):
        """
        Creates AttckMalware objects

        Returns:
            (AttckMalware) -- Returns a list of AttckMalware objects
        """
        if not self.__malwares:
            for malware in self.__attck['objects']:
                if malware['type'] == 'malware':
                    self.__malwares.append(AttckMalware(attck_obj=self.__attck, _enterprise_attck_obj=self.__enterprise_attck, **malware))
        return self.__malwares

    @property
    def techniques(self):
        """
        Creates AttckTechnique objects

        Returns:
            (AttckTechnique) -- Returns a list of AttckTechnique objects
        """
        if not self.__techniques:
            for technique in self.__attck["objects"]:
                if technique.get('type') == 'attack-pattern':
                    self.__techniques.append(AttckTechnique(attck_obj=self.__attck, _enterprise_attck_obj=self.__enterprise_attck, **technique))
        return self.__techniques

    def search_commands(self, search_term, json=False):
        """
        Search external datasets for potential commands using a search term

        Args:
            search_term (str): A command to search for close matches against
                               all external datasets containing potential commands

        Returns:
            list: A list of dictionaries containing the technique and the reason
                  for a close match
        """
        if json:
            import json
        return_list = []
        if not self.__ENTERPRISE_GENERATED_DATA_JSON:
            self.__ENTERPRISE_GENERATED_DATA_JSON = Configuration.get_data('generated_attck_json')
        for item in self.__ENTERPRISE_GENERATED_DATA_JSON['techniques']:
            if 'command_list' in item:
                if item['command_list']:
                    for cmd in item['command_list']:
                        if cmd:
                            if search_term in cmd:
                                for technique in self.techniques:
                                    if technique.id.lower() == item['technique_id'].lower():
                                        if json:
                                            return_list.append({
                                                'technique': json.dumps(str(technique))
                                            })
                                        else:
                                            return_list.append({
                                                'technique': technique,
                                                'command_list': technique.command_list
                                            })
        if return_list:
            return return_list
        else:
            return 'No similar commands found'
