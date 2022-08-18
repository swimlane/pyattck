# Copyright: (c) 2022, Swimlane <info@swimlane.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)
from .utils.logger import LoggingBase


class Base(metaclass=LoggingBase):

    config = None
    LOGO = "CgouX19fX19fICAgX19fXyAgICBfX19fICBfX18gICAuX19fX19fX19fX18uX19fX19fX19fX18uICBfX19fX18gIF9fICBfX18KfCAgIF8gIFwgIFwgICBcICAvICAgLyAvICAgXCAgfCAgICAgICAgICAgfCAgICAgICAgICAgfCAvICAgICAgfHwgIHwvICAvCnwgIHxfKSAgfCAgXCAgIFwvICAgLyAvICBeICBcIGAtLS18ICB8LS0tLWAtLS18ICB8LS0tLWB8ICAsLS0tLSd8ICAnICAvCnwgICBfX18vICAgIFxfICAgIF8vIC8gIC9fXCAgXCAgICB8ICB8ICAgICAgICB8ICB8ICAgICB8ICB8ICAgICB8ICAgIDwKfCAgfCAgICAgICAgICB8ICB8ICAvICBfX19fXyAgXCAgIHwgIHwgICAgICAgIHwgIHwgICAgIHwgIGAtLS0tLnwgIC4gIFwKfCBffCAgICAgICAgICB8X198IC9fXy8gICAgIFxfX1wgIHxfX3wgICAgICAgIHxfX3wgICAgICBcX19fX19ffHxfX3xcX19cCgo="
    FRAMEWORKS = ["enterprise", "ics", "mobile", "preattack"]
    ATTCK_TYPES = [
        "actors",
        "controls",
        "data_components",
        "data_sources",
        "malwares",
        "mitigations",
        "tactics",
        "techniques",
        "tools",
    ]
