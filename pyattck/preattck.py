from pyattck_data_models import MitreAttck

from .base import Base


class PreAttck(Base):
    """An interface to the MITRE ATT&CK Pre-Attck Framework.

    This class creates an interface to all data points in the
    MITRE ATT&CK Pre-Attck framework.

    This interface enables you to retrieve all properties within
    each item in the MITRE ATT&CK Pre-Attck Framework.

    The following categorical items can be accessed using this class:

        1. Actors
        2. Tactics
        3. Techniques

    As of pyattck 6.0.0, MITRE ATT&CK Frameworks are merged with generated datasets.
    These can be found [here](https://github.com/swimlane/pyattck-data)
    """

    __tactics = []
    __techniques = []
    __actors = []
    __attck = MitreAttck(**Base.config.get_data("pre_attck_json"))

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
