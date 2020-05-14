from .technique import MobileAttckTechnique
from .actor import MobileAttckActor
from .malware import MobileAttckMalware
from .tools import MobileAttckTools
from .mitigation import MobileAttckMitigation
from .tactic import MobileAttckTactic


class MobileAttck(object):

    '''
    This class creates an interface to all data points in the MITRE Mobile ATT&CK framework.

    This interface enables you to retrieve all properties within each item in the MITRE Mobile ATT&CK Framework.

    The following categorical items can be accessed using this class:

        1. Tactics (Tactics are the phases defined by MITRE Mobile ATT&CK)
        2. Techniques (Techniques are the individual actions which can accomplish a tactic)
        3. Mitigations (Mitigations are recommendations to prevent or protect against a technique)
        4. Actors (Actors or Groups are identified malicious actors/groups which have been identified and documented by MITRE & third-parties)
        5. Tools (Tools are software used to perform techniques)
        6. Malwares (Malwares are specific pieces of malware used by actors (or in general) to accomplish a technique)

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
            
            for technique in attck.mobile.techniques:
                print(technique.id)
                print(technique.name)
                print(technique.description)
                # etc.
            for mitigation in attck.mobile.mitigations:
                print(mitigation.id)
                print(mitigation.name)
                print(mitigation.description)
                # etc.

        2. To access relationship properties, do the following:

        .. code-block:: python

            from pyattck import Attck

            attck = Attck()
            
            for technique in attck.mobile.techniques:
                print(technique.id)
                print(technique.name)
                print(technique.description)
                # etc.

                for actor in technique.actors:
                    print(actor.id)
                    print(actor.name)
                    print(actor.description)
                    # etc.

            for mitigation in attck.mobile.mitigations:
                print(mitigation.id)
                print(mitigation.name)
                print(mitigation.description)
                # etc.

                for technique in mitigation.techniques:
                    print(technique.name)
                    print(technique.description)
                    # etc.
    '''

    __ENTERPRISE_GENERATED_DATA_JSON = None
    
    __tactics = None
    __techniques = None
    __mitigations = None
    __actors = None
    __tools = None
    __malwares = None
    
    def __init__(self, mobile_attck_json):
        """
        Sets standard properties that are found in all child classes as well as provides standard methods used by inherited classes

        Arguments:
            mobile_attck_json (json) - Takes the MITRE Mobile ATT&CK Json object as argument

        Returns:
            [MobileAttck]: Returns a Attck object that contains all data from the MITRE Mobile ATT&CK Framework
        """
        self.__mobile_attck = mobile_attck_json

    @property
    def actors(self):
        """Creates MobileAttckActor objects
        
        Returns:
            (MobileAttckActor) -- (Returns a list of MobileAttckActor objects)
        """
        if self.__actors is None:
            self.__actors = []
            for group in self.__mobile_attck['objects']:
                if group['type'] == 'intrusion-set':
                    self.__actors.append(MobileAttckActor(mobile_attck_obj=self.__mobile_attck, **group))
        return self.__actors

    @property
    def tactics(self):
        """Creates MobileAttckTactic objects
        
        Returns:
            (MobileAttckTactic) -- (Returns a list of MobileAttckTactic objects)
        """
        if self.__tactics is None:
            self.__tactics = []
            for tactic in self.__mobile_attck['objects']:
                if tactic['type'] == 'x-mitre-tactic':
                    self.__tactics.append(MobileAttckTactic(mobile_attck_obj=self.__mobile_attck, **tactic))
        return self.__tactics

    @property
    def mitigations(self):
        """Creates MobileAttckMitigation objects
        
        Returns:
            (MobileAttckMitigation) -- (Returns a list of MobileAttckMitigation objects)
        """
        if self.__mitigations is None:
            self.__mitigations = []
            for mitigation in self.__mobile_attck['objects']:
                if mitigation['type'] == 'course-of-action':
                    self.__mitigations.append(MobileAttckMitigation(mobile_attck_obj=self.__mobile_attck, **mitigation))
        return self.__mitigations

    @property
    def tools(self):
        """Creates MobileAttckTools objects
        
        Returns:
            (MobileAttckTools) -- Returns a list of MobileAttckTools objects
        """
        if self.__tools is None:
            self.__tools = []
            for tools in self.__mobile_attck['objects']:
                if tools['type'] == 'tool':
                    self.__tools.append(MobileAttckTools(mobile_attck_obj=self.__mobile_attck, **tools))
        return self.__tools

    @property
    def malwares(self):
        """Creates MobileAttckMalware objects
        
        Returns:
            (MobileAttckMalware) -- Returns a list of MobileAttckMalware objects
        """
        if self.__malwares is None:
            self.__malwares = []
            for malware in self.__mobile_attck['objects']:
                if malware['type'] == 'malware':
                    self.__malwares.append(MobileAttckMalware(mobile_attck_obj=self.__mobile_attck, **malware))
        return self.__malwares

    @property
    def techniques(self):
        """Creates MobileAttckTechnique objects
        
        Returns:
            (MobileAttckTechnique) -- Returns a list of MobileAttckTechnique objects
        """
        if self.__techniques is None:
            self.__techniques = []
            for technique in self.__mobile_attck["objects"]:
                if technique['type'] == 'attack-pattern':
                    self.__techniques.append(MobileAttckTechnique(mobile_attck_obj=self.__mobile_attck, **technique))
        return self.__techniques
    