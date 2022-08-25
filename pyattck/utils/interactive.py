"""Main interactive menu for pyattck."""
from ..base import Base
from .layout import CustomLayout
from .menu import Menu


class Interactive(Base):
    """Generates the interactive menu, options, and drives the display of the menu system."""

    _framework = None
    _type = None
    _object = None

    def __init__(self, attck_instance) -> None:
        """A pyattck Attck instance class."""
        self._attck_instance = attck_instance

    def generate(self):
        """Generates the interactive console for pyattck."""
        main_menu = Menu()
        main_menu.prompt = "Select the appropriate MITRE ATT&CK Framework:\n"
        for framework in self.FRAMEWORKS:
            obj_menu = Menu()
            obj_menu.prompt = "Select an entity below:\n"
            for obj in dir(getattr(self._attck_instance, framework)):
                if not obj.startswith("_") and obj in self.ATTCK_TYPES:
                    item_menu = Menu()
                    for item in getattr(getattr(self._attck_instance, framework), obj):
                        item_menu.add_option(getattr(item, "name"), CustomLayout(item))
                    obj_menu.add_option(obj, item_menu)
            main_menu.add_option(framework, obj_menu, True)
        main_menu.run()
