# Copyright: (c) 2022, Swimlane <info@swimlane.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import logging
import logging.config
import os
from logging import DEBUG, FileHandler

import yaml


class DebugFileHandler(FileHandler):
    def __init__(self, filename, mode="a", encoding=None, delay=False):
        super().__init__(filename, mode, encoding, delay)

    def emit(self, record):
        if not record.levelno == DEBUG:
            return
        super().emit(record)


class LoggingBase(type):
    def __init__(cls, *args):
        super().__init__(*args)
        cls.setup_logging()

        # Explicit name mangling
        logger_attribute_name = "_" + cls.__name__ + "__logger"

        # Logger name derived accounting for inheritance for the bonus marks
        logger_name = ".".join([c.__name__ for c in cls.mro()[-2::-1]])

        setattr(cls, logger_attribute_name, logging.getLogger(logger_name))

    def setup_logging(cls, default_path="./pyattck/data/logging.yml", default_level=logging.INFO, env_key="LOG_CFG"):
        """Setup logging configuration."""
        path = os.path.abspath(os.path.expanduser(os.path.expandvars(default_path)))
        value = os.getenv(env_key, None)
        if value:
            path = value
        if os.path.exists(os.path.abspath(path)):
            with open(path, "rt") as f:
                config = yaml.safe_load(f.read())
            logger = logging.config.dictConfig(config)
        else:
            logger = logging.basicConfig(level=default_level)
