from .technique import AttckTechnique
from .actor import AttckActor
from .malware import AttckMalware
from .tools import AttckTools
from .mitigation import AttckMitigation
from .tactic import AttckTactic


class Enterprise(object):

    '''
        This class creates an interface to all data points in the MITRE ATT&CK Enterprise framework.

        This interface enables you to retrieve all properties within each item in the MITRE ATT&CK Enterprise Framework.

        The following categorical items can be accessed using this class:

            1. Tactics (Tactics are the phases defined by MITRE ATT&CK)
            2. Techniques (Techniques are the individual actions which can accomplish a tactic)
            3. Mitigations (Mitigations are recommendations to prevent or protect against a technique)
            4. Actors (Actors or Groups are identified malicious actors/groups which have been identified and documented by MITRE & third-parties)
            5. Tools (Tools are software used to perform techniques)
            6. Malwares (Malwares are specific pieces of malware used by actors (or in general) to accomplish a technique)
        
        You can also search the external dataset for external commands that are similar using the `search_commands` method.

           .. code-block:: python
               
               from pyattck import Attck

               attck = Attck()
               
               for search in attck.enterprise.search_commands('powershell'):
                   print(search['technique'])
                   print(search['reason_for_match'])

        Additionally, as of pyattck 2.0.0 you can now access additional datasets related to a technique.
        These datasets are [documented here](https://github.com/swimlane/pyattck/blob/master/generateattcks/README.md).

        Each technique enables you to access the following properties on the object:

            1. command_list - A list of commands associated with a technique
            2. commands = A list of dictionary objects containing source, command, and provided name associated with a technique
            3. queries = A list of dictionary objects containing product, query, and name associated with a technique
            4. datasets = A list of raw datasets associated with a technique
            5. possible_detections = A list of raw datasets containing possible detection methods for a technique

        Each Actor object (if available) enables you to access the following properties on the object:

            1. country
            2. operations
            3. attribution_links
            4. known_tools
            5. targets
            6. additional_comments
            7. external_description

        You can retrieve the entire dataset using the `external_dataset` property on a `actor` object.

        pyattck also enables you to retrieve or generate logos for the actor or group using the following properties:
        
            - ascii_logo - Generated ASCII logo based on the actor or groups name
            - image_logo - Generated ASCII logo based on a provided logo

        Each Tools object (if available) enables you to access the following properties on the object:

            1. additional_names
            2. attribution_links
            3. additional_comments
            4. family

        You can retrieve the entire dataset using the `external_dataset` property on a `tool` object.

        You can also access external data properties from the C2 Matrix project. The following properties are generated using C2 Matrix external data:

            - HTTP
            - Implementation
            - Custom Profile
            - DomainFront
            - Multi-User
            - SMB
            - Kill Date
            - macOS
            - GitHub
            - Key Exchange
            - Chaining
            - Price
            - TCP
            - Proxy Aware
            - HTTP3
            - HTTP2
            - Date
            - Evaluator
            - Working Hours
            - Slack
            - FTP
            - Version Reviewed
            - Logging
            - Name
            - License
            - Windows
            - Stego
            - Notes
            - Server
            - Actively Maint.
            - Dashboard
            - DNS
            - Popular Site
            - ICMP
            - IMAP
            - DoH
            - Jitter
            - How-To
            - ATT&CK Mapping
            - Kali
            - Twitter
            - MAPI
            - Site
            - Agent
            - API
            - UI
            - Linux

        You can retrieve the entire dataset using the `c2_data` property.

    
    Example:
        Once an Attck object is instantiated, you can access each object type as a list of objects (e.g. techniques, tactics, actors, etc.)

        You can iterate over each object list and access specific properties and relationship properties of each.
        
        The following relationship properties are accessible:
            1. Actors
                1. Tools used by the Actor or Group
                2. Malware used by the Actor or Group
                3. Techniques this Actor or Group uses
            2. Malwares
                1. Actor or Group(s) using this malware
                2. Techniques this malware is used with
            3. Mitigations
                1. Techniques related to a specific set of mitigation suggestions
            4. Tactics
                1. Techniques found in a specific Tactic (phase)
            5. Techniques
                1. Tactics a technique is found in
                2. Mitigation suggestions for a given technique
                3. Actor or Group(s) identified as using this technique
            6. Tools
                1. Techniques that the specified tool is used within
                2. Actor or Group(s) using a specified tool
        
            1. To iterate over a list, do the following:

            .. code-block:: python
               
               from pyattck import Attck

               attck = Attck()
               
               for technique in attck.enterprise.techniques:
                   print(technique.id)
                   print(technique.name)
                   print(technique.description)
                   # etc.

               for mitigation in attck.enterprise.mitigations:
                   print(mitigation.id)
                   print(mitigation.name)
                   print(mitigation.description)
                   # etc.

            2. To access relationship properties, do the following:

            .. code-block:: python

               from pyattck import Attck

               attck = Attck()
               
               for technique in attck.enterprise.techniques:
                   print(technique.id)
                   print(technique.name)
                   print(technique.description)
                   # etc.

                   for actor in technique.actors:
                       print(actor.id)
                       print(actor.name)
                       print(actor.description)
                       # etc.

               for mitigation in attck.enterprise.mitigations:
                   print(mitigation.id)
                   print(mitigation.name)
                   print(mitigation.description)
                   # etc.

                   for technique in mitigation.techniques:
                       print(technique.name)
                       print(technique.description)
                       # etc.

    Arguments:
        attck_json (json) - The attck_json is supplied by the attck.py module when instantiated.

    Returns:
        [Attck]: Returns a Attck object that contains all data from the MITRE ATT&CK Framework
    '''

    __ENTERPRISE_GENERATED_DATA_JSON = None
    
    __tactics = None
    __techniques = None
    __mitigations = None
    __actors = None
    __tools = None
    __malwares = None
    
    def __init__(self, attck_json, nested_subtechniques=True):
        """
        Sets standard properties that are found in all child classes as well as provides standard methods used by inherited classes
        
        Arguments:
            kwargs (dict) -- Takes the MITRE ATT&CK Json object as a kwargs values
            nested_subtechniques (bool) -- Determines if nested subtechniques will be used or not. This is passed from attck class
        """
        self.__attck = attck_json
        self.__nested_subtechniques = nested_subtechniques

    @property
    def actors(self):
        """Creates AttckActor objects
        
        Returns:
            (AttckActor) -- (Returns a list of AttckActor objects)
        """
        if self.__actors is None:
            self.__actors = []
            for group in self.__attck['objects']:
                if group['type'] == 'intrusion-set':
                    self.__actors.append(AttckActor(attck_obj=self.__attck, **group))
        return self.__actors

    @property
    def tactics(self):
        """Creates AttckTactic objects
        
        Returns:
            (AttckTactic) -- (Returns a list of AttckTactic objects)
        """
        if self.__tactics is None:
            self.__tactics = []
            for tactic in self.__attck['objects']:
                if tactic['type'] == 'x-mitre-tactic':
                    self.__tactics.append(AttckTactic(attck_obj=self.__attck, **tactic))
        return self.__tactics

    @property
    def mitigations(self):
        """Creates AttckMitigation objects
        
        Returns:
            (AttckMitigation) -- (Returns a list of AttckMitigation objects)
        """
        if self.__mitigations is None:
            self.__mitigations = []
            for mitigation in self.__attck['objects']:
                if mitigation['type'] == 'course-of-action':
                    self.__mitigations.append(AttckMitigation(attck_obj=self.__attck, **mitigation))
        return self.__mitigations

    @property
    def tools(self):
        """Creates AttckTools objects
        
        Returns:
            (AttckTools) -- Returns a list of AttckTools objects
        """
        if self.__tools is None:
            self.__tools = []
            for tools in self.__attck['objects']:
                if tools['type'] == 'tool':
                    self.__tools.append(AttckTools(attck_obj=self.__attck, **tools))
        return self.__tools

    @property
    def malwares(self):
        """Creates AttckMalware objects
        
        Returns:
            (AttckMalware) -- Returns a list of AttckMalware objects
        """
        if self.__malwares is None:
            self.__malwares = []
            for malware in self.__attck['objects']:
                if malware['type'] == 'malware':
                    self.__malwares.append(AttckMalware(attck_obj=self.__attck, **malware))
        return self.__malwares

    @property
    def techniques(self):
        """Creates AttckTechnique objects
        
        Returns:
            (AttckTechnique) -- Returns a list of AttckTechnique objects
        """
        if self.__techniques is None:
            subtechniques = []
            self.__techniques = []
            for technique in self.__attck["objects"]:
                if technique.get('type') == 'attack-pattern' and technique.get('revoked') is not True:
                    if self.__nested_subtechniques:
                        if technique.get('x_mitre_is_subtechnique'):
                            subtechniques.append(technique)
                        else:
                            self.__techniques.append(AttckTechnique(attck_obj=self.__attck, **technique))
                    else:
                        self.__techniques.append(AttckTechnique(attck_obj=self.__attck, **technique))

            if subtechniques:
                for item in subtechniques:
                    if item.get('external_references'):
                        for p in item.get('external_references'):
                            for s in p:
                                if p[s] == 'mitre-attack':
                                    for technique in self.__techniques:
                                        if p['external_id'].split('.')[0] == technique.id:
                                            technique.subtechniques = AttckTechnique(attck_obj=self.__attck, **item)
        return self.__techniques
   

    def search_commands(self, search_term, json=False):
        """Search external datasets for potential commands using a search term  
        
        Args:
            search_term (str): A command to search for close matches against all external datasets containing potential commands
        
        Returns:
            list: A list of dictionaries containing the technique and the reason for a close match
        """
        if json:
            import json
        from ..datasets import AttckDatasets
        return_list = []
        if not Enterprise.__ENTERPRISE_GENERATED_DATA_JSON:
            Enterprise.__ENTERPRISE_GENERATED_DATA_JSON = AttckDatasets().generated_attck_data()
        for item in Enterprise.__ENTERPRISE_GENERATED_DATA_JSON['techniques']:
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
