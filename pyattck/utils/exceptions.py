class GeneratedDatasetException(Exception):

    """
    Raised when unable to retrieve generated datasets and related properties
    """
    pass

class ConfigurationException(Exception):

    """Raised when unable to load or read the pyattck configuration file.
    """
    pass

class UnknownFileError(ValueError):
    """Raised when the provided file extension is unkown or is not json, yml or yaml
    """
    def __init__(self, provided_value=None, known_values=None):
        if provided_value and known_values:
            if isinstance(known_values, list):
                super().__init__("The provided value {} is unknown. Please provide a file path with one of these '{}' extensions.".format(
                    provided_value,
                    ','.join([x for x in known_values])
                ))
        else:
            pass