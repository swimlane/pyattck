from .base import Base
from pyattck_data_models import MitreAttck, NistControls


class EnterpriseAttck(Base):
    """An interface to the MITRE ATT&CK Enterprise Framework.

    This class creates an interface to all data points in the
    MITRE ATT&CK Enterprise framework.

    This interface enables you to retrieve all properties within
    each item in the MITRE ATT&CK Enterprise Framework.

    The following categorical items can be accessed using this class:

        1. Actors
        2. Controls
        3. Data Sources
        4. Data Components
        5. Malware
        6. Mitigations
        7. Tactics
        8. Techniques
        9. Tools

    As of pyattck 6.0.0, MITRE ATT&CK Frameworks are merged with generated datasets.
    These can be found [here](https://github.com/swimlane/pyattck-data)
    """

    __tactics = []
    __techniques = []
    __mitigations = []
    __actors = []
    __tools = []
    __malwares = []
    __controls = []
    __data_sources = []
    __data_components = []
    __nist_controls_json = NistControls(**Base.config.get_data("nist_controls_json"))
    __attck = MitreAttck(**Base.config.get_data("enterprise_attck_json"))

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
    def controls(self):
        """Retrieves Control objects.

        Returns:
            (Control) -- Returns a list of Control objects
        """
        if not self.__controls:
            if self.__nist_controls_json.objects:
                for control in self.__nist_controls_json.objects:
                    if control.type == "course-of-action":
                        self.__controls.append(control)
        return self.__controls

    @property
    def data_components(self):
        """Retrieves DataComponent objects.

        Returns:
            (DataComponent) -- Returns a list of DataComponent objects
        """
        if not self.__data_components:
            for item in self.__attck.objects:
                if item.type == "x-mitre-data-component":
                    self.__data_components.append(item)
        return self.__data_components

    @property
    def data_sources(self):
        """Retrieves DataSource objects.

        Returns:
            (DataSource) -- Returns a list of DataSource objects
        """
        if not self.__data_sources:
            for item in self.__attck.objects:
                if item.type == "x-mitre-data-source":
                    self.__data_sources.append(item)
        return self.__data_sources

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
