# Copyright: (c) 2022, Swimlane <info@swimlane.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)
from .utils.logger import LoggingBase


class Base(metaclass=LoggingBase):

    config = None
