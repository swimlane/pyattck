from pyattck_data.attack import MitreAttck

from .base import Base


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
            self.__actors = [x for x in self.__attck.objects if x.type == "intrusion-set"]
        return self.__actors

    @property
    def malwares(self):
        """Retrieves Malware objects.

        Returns:
            (Malware) -- Returns a list of Malware objects
        """
        if not self.__malwares:
            self.__malwares = [x for x in self.__attck.objects if x.type == "malware"]
        return self.__malwares

    @property
    def mitigations(self):
        """Retrieves Mitigation objects.

        Returns:
            (Mitigation) -- (Returns a list of Mitigation objects)
        """
        if not self.__mitigations:
            self.__mitigations = [x for x in self.__attck.objects if x.type == "course-of-action"]
        return self.__mitigations

    @property
    def tactics(self):
        """Retrieves Tactic objects.

        Returns:
            (Tactic) -- (Returns a list of Tactic objects)
        """
        if not self.__tactics:
            self.__tactics = [x for x in self.__attck.objects if x.type == "x-mitre-tactic"]
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
            self.__tools = [x for x in self.__attck.objects if x.type == "tool"]
        return self.__tools
