from pyattck_data.attack import MitreAttck
from pyattck_data.nist import NistControls

from .base import Base


class ICSAttck(Base):
    """An interface to the MITRE ATT&CK ICS (Industrial Control Systems) Framework.

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
        5. Controls (Controls related to mitigations and techniques)
        6. Data sources
        7. Data Components

    As of pyattck 6.0.0, MITRE ATT&CK Frameworks are merged with generated datasets.
    These can be found [here](https://github.com/swimlane/pyattck-data)

    """

    __tactics = []
    __techniques = []
    __mitigations = []
    __malwares = []
    __controls = []
    __data_sources = []
    __data_components = []
    __nist_controls_json = NistControls(**Base.config.get_data("nist_controls_json"))
    __attck = MitreAttck(**Base.config.get_data("ics_attck_json"))

    @property
    def controls(self):
        """Retrieves Control objects.

        Returns:
            (Control) -- Returns a list of Control objects
        """
        if not self.__controls:
            if self.__nist_controls_json.objects:
                self.__controls = [x for x in self.__nist_controls_json.objects if x.type == "course-of-action"]
        return self.__controls

    @property
    def data_components(self):
        """Retrieves DataComponent objects.

        Returns:
            (DataComponent) -- Returns a list of DataComponent objects
        """
        if not self.__data_components:
            self.__data_components = [x for x in self.__attck.objects if x.type == "x-mitre-data-component"]
        return self.__data_components

    @property
    def data_sources(self):
        """Retrieves DataSource objects.

        Returns:
            (DataSource) -- Returns a list of DataSource objects
        """
        if not self.__data_sources:
            self.__data_sources = [x for x in self.__attck.objects if x.type == "x-mitre-data-source"]
        return self.__data_sources

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
