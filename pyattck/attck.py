from .base import Base
from .configuration import Configuration, Options


class Attck(Base):

    """Interface to all MITRE ATT&CK frameworks.

    Currently, this class enables access to the Enterprise & PRE-ATT&CK
    frameworks with others coming soon.  To access each framework, use
    the following properties

        * enterprise
        * preattack
        * ics
        * mobile

    This interface enables you to retrieve all properties within each
    item in the MITRE ATT&CK Frameworks (as applicable).

    The following categorical items can be accessed using this class:

        1. Tactics (Tactics are the phases defined by MITRE ATT&CK)
        2. Techniques (Techniques are the individual actions which can
            accomplish a tactic)
        3. Mitigations (Mitigations are recommendations to prevent or
            protect against a technique)
        4. Actors (Actors or Groups are identified malicious
            actors/groups which have been identified and documented by
            MITRE & third-parties)
        5. Tools (Tools are software used to perform techniques)
        6. Malwares (Malwares are specific pieces of malware used by
            actors (or in general) to accomplish a technique)

    You can access additional datasets related to a technique.
    These datasets are [documented here](https://github.com/swimlane/pyattck-data).

    Example:
        Once an `Attck` object is instantiated, you can access each object
        type as a list of objects (e.g. techniques, tactics, actors, etc.)

        You can iterate over each object list and access specific properties
        and relationship properties of each.

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

                   for actor in technique.enterprise.actors:
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
        nested_subtechniques (bool, optional): Whether not to iterate over nested subtechniques. Defaults to True.
        use_config (bool, optional): Specifies if a configuration file should be used or not.  Defaults to False.
        save_config (bool, optional): Specifies if pyattck should save a configuration file based on the provided
                                      values.  Defaults to False.
        config_file_path (str, optional): Path to a yaml configuration file which contains two key value pairs.
                                          Defaults to '~/pyattck/config.yml'.
        data_path (str, optional): Path to store the external data locally on your system. Defaults to '~/pyattck/data'.
        enterprise_attck_json (str, optional): A URL or local file path to the MITRE ATT&CK Json file.
                        Defaults to https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_enterprise_attck_v1.json.
        pre_attck_json (str, optional): A URL or local file path to the MITRE Pre-ATT&CK Json file.
                        Defaults to https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_pre_attck_v1.json.
        mobile_attck_json (str, optional): A URL or local file path to the MITRE Mobile ATT&CK Json file.
                        Defaults to https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_mobile_attck_v1.json.
        ics_attck_json (str, optional): A URL or local file path to the MITRE ICS ATT&CK JSON file.
                        Defaults to https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_ics_attck_v1.json.
        nist_controls_json (str, optional): A URL or local file path to the NIST Controls Json file.
                        Defaults to https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_nist_controls_v1.json.
        generated_nist_json (str, optional): A URL or local file path to the Generated NIST Controls Mapping Json file.
                        Defaults to https://swimlane-pyattck.s3.us-west-2.amazonaws.com/attck_to_nist_controls.json.
        kwargs (dict, optional): Provided kwargs will be passed to any HTTP requests using the Requests library.
                                 Defaults to None.

    Returns:
        [Attck]: Returns a Attck object that contains all data from MITRE ATT&CK Frameworks
    """

    def __init__(
        self,
        nested_subtechniques=True,
        use_config=False,
        save_config=False,
        config_file_path="~/pyattck/config.yml",
        data_path="~/pyattck/data",
        enterprise_attck_json="https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_enterprise_attck_v1.json",
        pre_attck_json="https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_pre_attck_v1.json",
        mobile_attck_json="https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_mobile_attck_v1.json",
        ics_attck_json="https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_ics_attck_v1.json",
        nist_controls_json="https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_nist_controls_v1.json",
        generated_nist_json="https://swimlane-pyattck.s3.us-west-2.amazonaws.com/attck_to_nist_controls.json",
        **kwargs
    ):
        """
        The main entry point for pyattck.

        When instantiating an Attck object you can specify if you want the
        new subtechniques to be nested underneath their parent techniques
        or not.

        Setting nested_subtechniques to False will result in all techniques
        accessible under the techniques property. If using the default value
        of True, subtechniques will be accessible underneath
        technique.subtechniques.

        When instantiating an Attck object you can access either the
        Enterprise, PRE-ATT&CK, or Mobile MITRE Frameworks.  Specify
        one of the following properties to access the frameworks specific
        data:

            * enterprise
            * preattack
            * mobile
            * ics

        You can specify an alternate location of a local copy of the
        following objects:

            1. config_file_path = Path to a yaml configuration file
                                  which contains two key value pairs
                Example content:

                config_file_path: /Users/user.name/pyattck/config.yml
                data_path: /Users/user.name/pyattck/data
                enterprise_attck_json: https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_enterprise_attck_v1.json
                generated_nist_json: https://swimlane-pyattck.s3.us-west-2.amazonaws.com/attck_to_nist_controls.json
                mobile_attck_json: https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_mobile_attck_v1.json
                ics_attck_json: https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_ics_attck_v1.json
                nist_controls_json: https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_nist_controls_v1.json
                pre_attck_json: https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_pre_attck_v1.json

            2. data_path = The path to hold the external data locally on your system.
                           The default is your user home path.

        Args:
            nested_subtechniques (bool, optional): Whether not to iterate over nested subtechniques. Defaults to True.
            use_config (bool, optional): Specifies if a configuration file should be used or not.  Defaults to False.
            save_config (bool, optional): Specifies if pyattck should save a configuration file based on the
                                          provided values.  Defaults to False.
            config_file_path (str, optional): Path to a yaml configuration file which contains two key value pairs.
                                              Defaults to '~/pyattck/config.yml'.
            data_path (str, optional): Path to store the external data locally on your system.
                                       Defaults to '~/pyattck/data'.
            enterprise_attck_json (str, optional): A URL or local file path to the MITRE ATT&CK Json file.
                        Defaults to https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_enterprise_attck_v1.json.
            pre_attck_json (str, optional): A URL or local file path to the MITRE Pre-ATT&CK Json file.
                        Defaults to https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_pre_attck_v1.json.
            mobile_attck_json (str, optional): A URL or local file path to the MITRE Mobile ATT&CK Json file.
                        Defaults to https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_mobile_attck_v1.json.
            ics_attck_json (str, optional): A URL or local file path to the MITRE ICS ATT&CK JSON file.
                        Defaults to https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_ics_attck_v1.json.
            nist_controls_json (str, optional): A URL or local file path to the NIST Controls Json file.
                        Defaults to https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_nist_controls_v1.json
            generated_nist_json (str, optional): A URL or local file path to the Generated NIST Controls Mapping Json
                        file. Defaults to https://swimlane-pyattck.s3.us-west-2.amazonaws.com/attck_to_nist_controls.json.
            kwargs (dict, optional): Provided kwargs will be passed to any HTTP requests using the Requests library.
                                     Defaults to None.
        """
        Base.config = Options(
            nested_subtechniques=nested_subtechniques,
            use_config=use_config,
            save_config=save_config,
            config_file_path=config_file_path,
            kwargs=kwargs,
            config=Configuration(
                data_path=data_path,
                enterprise_attck_json=enterprise_attck_json,
                pre_attck_json=pre_attck_json,
                mobile_attck_json=mobile_attck_json,
                ics_attck_json=ics_attck_json,
                nist_controls_json=nist_controls_json,
                generated_nist_json=generated_nist_json,
            ),
        )

    @property
    def enterprise(self):
        """Retrieve objects from the Enterprise MITRE ATT&CK Framework.

        Returns:
            Enterprise: Returns an Enterprise object
        """
        from .enterprise import EnterpriseAttck

        self.__logger.debug("Calling MITRE Enterprise ATT&CK Framework")
        return EnterpriseAttck()

    @property
    def preattack(self):
        """Retrieve objects from the MITRE PRE-ATT&CK Framework.

        Returns:
            PreAttack: Returns an PreAttack object
        """
        from .preattck import PreAttck

        self.__logger.debug("Calling MITRE Pre-ATT&CK Framework")
        return PreAttck()

    @property
    def mobile(self):
        """Retrieve objects from the MITRE Mobile ATT&CK Framework.

        Returns:
            PreAttack: Returns an MobileAttack object
        """
        from .mobile import MobileAttck

        self.__logger.debug("Calling MITRE Mobile ATT&CK Framework")
        return MobileAttck()

    @property
    def ics(self):
        """Retrieve objects from the MITRE ICS ATT&CK Framework.

        Returns:
            PreAttack: Returns an ICSAttck object
        """
        from .ics import ICSAttck

        self.__logger.debug("Calling MITRE ICS ATT&CK Framework")
        return ICSAttck()

    def update(self) -> bool:
        """Updates the local cached JSON files."""
        return True if Base.config._save_json_data(force=True) else False
