from .base import Base
from pyattck_data_models import MitreAttck


class MobileAttck(Base):
    """An interface to the MITRE ATT&CK Mobile Framework.

    This class creates an interface to all data points in the
    MITRE ATT&CK Mobile framework.

    This interface enables you to retrieve all properties within
    each item in the MITRE ATT&CK Mobile Framework.

    The following categorical items can be accessed using this class:

        1. Actors
        2. Malware
        3. Mitigations
        4. Tactics
        5. Techniques
        6. Tools

    As of pyattck 6.0.0, MITRE ATT&CK Frameworks are merged with generated datasets.
    These can be found [here](https://github.com/swimlane/pyattck-data)
    """

    __tactics = []
    __techniques = []
    __mitigations = []
    __actors = []
    __tools = []
    __malwares = []
    __attck = MitreAttck(**Base.config.get_data("mobile_attck_json"))

    @property
    def actors(self):
        """Retrieves Actor objects.

        Returns:
            (Actor) -- (Returns a list of Actor objects)
        """
        if not self.__actors:
            for actor in self.__attck.objects:
                if actor.type == "intrusion-set":
                    self.__actors.append(actor)
        return self.__actors

    @property
    def malwares(self):
        """Retrieves Malware objects.

        Returns:
            (Malware) -- Returns a list of Malware objects
        """
        if not self.__malwares:
            for item in self.__attck.objects:
                if item.type == "malware":
                    self.__malwares.append(item)
        return self.__malwares

    @property
    def mitigations(self):
        """Retrieves Mitigation objects.

        Returns:
            (Mitigation) -- (Returns a list of Mitigation objects)
        """
        if not self.__mitigations:
            for item in self.__attck.objects:
                if item.type == "course-of-action":
                    self.__mitigations.append(item)
        return self.__mitigations

    @property
    def tactics(self):
        """Retrieves Tactic objects.

        Returns:
            (Tactic) -- (Returns a list of Tactic objects)
        """
        if not self.__tactics:
            for item in self.__attck.objects:
                if item.type == "x-mitre-tactic":
                    self.__tactics.append(item)
        return self.__tactics

    @property
    def techniques(self):
        """Retrieves Technique objects.

        Returns:
            (Technique) -- Returns a list of Technique objects
        """
        if not self.__techniques:
            for item in self.__attck.objects:
                if item.type == "attack-pattern":
                    if item.techniques and not Base.config.nested_subtechniques:
                        for i in item.techniques:
                            self.__techniques.append(i)
                    self.__techniques.append(item)
        return self.__techniques

    @property
    def tools(self):
        """Retrieves Tool objects.

        Returns:
            (Tool) -- Returns a list of Tool objects
        """
        if not self.__tools:
            for item in self.__attck.objects:
                if item.type == "tool":
                    self.__tools.append(item)
        return self.__tools
