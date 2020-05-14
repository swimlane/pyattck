from .technique import PreAttckTechnique
from .actor import PreAttckActor
from .tactic import PreAttckTactic


class PreAttck(object):

    '''
        This class creates an interface to all data points in the MITRE PRE-ATT&CK framework.

        This interface enables you to retrieve all properties within each item in the MITRE PRE-ATT&CK Framework.

        The following categorical items can be accessed using this class:

            1. Tactics (Tactics are the phases defined by MITRE ATT&CK)
            2. Techniques (Techniques are the individual actions which can accomplish a tactic)
            3. Actors (Actors or Groups are identified malicious actors/groups which have been identified and documented by MITRE & third-parties)

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

    
    Example:
        Once an Attck object is instantiated, you can access each object type as a list of objects (e.g. techniques, tactics, actors, etc.)

        You can iterate over each object list and access specific properties and relationship properties of each.
        
        The following relationship properties are accessible:
            1. Actors
                1. Techniques this Actor or Group uses
            2. Tactics
                1. Techniques found in a specific Tactic (phase)
            3. Techniques
                1. Tactics a technique is found in
                2. Actor or Group(s) identified as using this technique
        
            1. To iterate over a list, do the following:

            .. code-block:: python
               
               from pyattck import Attck

               attck = Attck()
               
               for technique in attck.preattack.techniques:
                   print(technique.id)
                   print(technique.name)
                   print(technique.description)
                   # etc.
               

            2. To access relationship properties, do the following:

            .. code-block:: python

               from pyattck import Attck

               attck = Attck()
               
               for technique in attck.preattack.techniques:
                   print(technique.id)
                   print(technique.name)
                   print(technique.description)
                   # etc.

                   for actor in technique.actors:
                       print(actor.id)
                       print(actor.name)
                       print(actor.description)
                       # etc.
    '''
    
    __tactics = None
    __techniques = None
    __mitigations = None
    __actors = None
    __tools = None
    __malwares = None
    
    def __init__(self, preattck_json):
        """
        Sets standard properties that are found in all child classes as well as provides standard methods used by inherited classes

        Arguments:
            preattck_json (json) - Takes the MITRE PRE-ATT&CK Json object as argument

        Returns:
            [PreAttck]: Returns a Attck object that contains all data from the MITRE PRE-ATT&CK Framework
        """
        self.__preattck = preattck_json

    @property
    def actors(self):
        """Access all actors within the MITRE PRE-ATT&CK Framework
        
        Returns:
            PreAttckActor: Returns a list of PreAttckActor objects
        """
        if self.__actors is None:
            self.__actors = []
            for group in self.__preattck['objects']:
                if group['type'] == 'intrusion-set':
                    self.__actors.append(PreAttckActor(preattck_obj=self.__preattck, **group))
        return self.__actors

    @property
    def tactics(self):
        """Access all tactics within the MITRE PRE-ATT&CK Framework
        
        Returns:
            PreAttckTactic: Returns a list of PreAttckTactic objects
        """
        if self.__tactics is None:
            self.__tactics = []
            for tactic in self.__preattck['objects']:
                if tactic['type'] == 'x-mitre-tactic':
                    self.__tactics.append(PreAttckTactic(preattck_obj=self.__preattck, **tactic))
        return self.__tactics


    @property
    def techniques(self):
        """Access all techniques within the MITRE PRE-ATT&CK Framework
                
        Returns:
            PreAttckTechnique: Returns a list of PreAttckTechnique objects
        """
        if self.__techniques is None:
            self.__techniques = []
            for technique in self.__preattck["objects"]:
                if (technique['type'] == 'attack-pattern'):
                    self.__techniques.append(PreAttckTechnique(preattck_obj=self.__preattck, **technique))
        return self.__techniques
