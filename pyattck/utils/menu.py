"""Menu for interactive console within pyattck."""
import base64
import os
from typing import List

from ..base import Base


class Menu(Base):
    """Menu to control flow of the interactive menu."""

    def __init__(self):
        """Creates a new instance of a Menu class object."""
        self.options = {}
        self._option_number = 0
        self._selected_option = None
        self.prompt = "Please choose an option:"
        self.error_text = "Error! Please enter a valid option."
        self._logo_displayed = False

    @property
    def prompt(self) -> str:
        """The prompt question to use when using this menu."""
        return self._prompt

    @prompt.setter
    def prompt(self, value: str) -> None:
        """Sets the prompt question to use when using this menu."""
        self._prompt = value

    @property
    def error_text(self) -> str:
        """The error text for this menu."""
        return self._error_text

    @error_text.setter
    def error_text(self, value: str) -> None:
        """Sets the error text for the current menu."""
        self._error_text = value

    @property
    def selected_option(self) -> List[str]:
        """Returns the currently selected option."""
        if self._selected_option:
            return self.options[self._selected_option]
        return None

    @selected_option.setter
    def selected_option(self, value: int) -> None:
        """Sets the currently selected option from the options list."""
        self._selected_option = value

    def cls(self) -> None:
        """Clears the current screen."""
        os.system("cls" if os.name == "nt" else "clear")

    def display_error(self) -> None:
        """Displays the defined error message with padding as needed."""
        print(f"\n{self.error_text}\n")

    def display_menu(self, clear_screen: bool = False) -> None:
        """Displays the current menu options."""
        if clear_screen:
            self.cls()
        print(self.prompt)
        for i in range(1, len(self.options) + 1):
            print(f"{i} - {self.options[i][0]}")

    def add_option(self, name: str, option: object or None, triggers_exit: bool = False) -> None:
        """Adds an option to the menu option list."""
        self._option_number += 1
        self.options[self._option_number] = [name, option, triggers_exit]

    def run(self) -> None:
        """Main method to display the current menu, as well as all provided sub-menus."""
        user_input = ""
        if not self._logo_displayed:
            self.cls()
            print(base64.b64decode(self.LOGO).decode("ascii"))
            self._logo_displayed = True
        self.display_menu()
        while True:
            user_input = input("\nYour selection: ")
            try:
                user_input = int(user_input)
                if user_input <= 0 or user_input > len(self.options):
                    self.display_error()
                else:
                    if callable(self.options[user_input][1]):
                        self.selected_option = user_input
                        self.options[user_input][1]()
                        if self.options[user_input][2]:
                            return
                        else:
                            self.display_menu()
                    elif self.options[user_input][1]:
                        self.selected_option = user_input
                        self.options[user_input][1].run()
                        self.display_menu(clear_screen=True)
                    else:
                        return
            except ValueError:
                self.display_error()
