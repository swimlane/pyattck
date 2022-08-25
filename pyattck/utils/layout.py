"""Used to format interactive layout display for individual attack component types."""
from datetime import datetime
from time import sleep

from rich import box
from rich.align import Align
from rich.console import Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..base import Base


class Footer(Base):
    """Display footer references."""

    def __init__(self, item):
        """Provided the object type item we generate references and display them on the footer.

        The following attack types are expected:

        "actors","controls","data_components","data_sources","malwares","mitigations","tactics","techniques","tools"

        Args:
            item (Any): A attack type object.
        """
        self.item = item

    def __rich__(self) -> Panel:
        """Generates a Panel object with the correct relationships.

        Returns:
            Panel: A footer relationship Panel object.
        """
        grid = Table.grid(expand=True)
        grid.add_column(justify="center", ratio=1)
        grid.add_column(justify="right")
        panel_list = []
        for item in dir(self.item):
            if not item.startswith("_") and item in self.ATTCK_TYPES:
                if getattr(self.item, item):
                    name_list = set()
                    for i in getattr(self.item, item):
                        name_list.add(getattr(i, "name"))
                    panel_list.append(
                        Panel(
                            ", ".join([x for x in list(name_list)]),
                            title=f"[b]{item}",
                            border_style="red",
                            padding=(1, 2),
                        ),
                    )
        grid.add_row(*panel_list)
        return Panel(grid, style="white on blue")


class Header:
    """Display header with clock."""

    def __init__(self, item):
        """Provided the object type item we generate references and display them on the footer.

        The following attack types are expected:

        "actors","controls","data_components","data_sources","malwares","mitigations","tactics","techniques","tools"

        Args:
            item (Any): A attack type object.
        """
        self.item = item

    def __rich__(self) -> Panel:
        """Returns the header which contains the items name and any aliases.

        Returns:
            Panel: A header Panel object.
        """
        grid = Table.grid(expand=True)
        grid.add_column(justify="center", ratio=1)
        grid.add_column(justify="right")
        if hasattr(self.item, "aliases"):
            text = f"[b]{self.item.name}[/b] - Known Aliases: {', '.join([x for x in self.item.aliases])}"
        else:
            text = f"[b]{self.item.name}[/b]"

        grid.add_row(
            text,
            datetime.now().ctime().replace(":", "[blink]:[/]"),
        )
        return Panel(grid, style="white on blue")


class CustomLayout(Base):
    """Used to generate a custom layout for pyattck object items."""

    def __init__(self, item):
        """Provided the object type item we generate references and display them on the footer.

        The following attack types are expected:

        "actors","controls","data_components","data_sources","malwares","mitigations","tactics","techniques","tools"

        Args:
            item (Any): A attack type object.
        """
        self.item = item
        layout = self.make_layout()
        layout["header"].update(Header(self.item))
        layout["body"].update(self.make_general_information())
        layout["side"].update(Panel(self.make_top_left_box(), title="Details", border_style="red"))
        layout["footer"].update(Footer(self.item))
        self.layout = layout

    def run(self):
        """Main callable for the CustomLayout class.

        This method gets called within the Menu class when a wrapped object is passed to display this
        custom layout within the console.
        """
        with Live(self.layout, refresh_per_second=10, screen=True, redirect_stderr=False) as live:
            try:
                while True:
                    sleep(1)
            except KeyboardInterrupt:
                pass

    def make_layout(self) -> Layout:
        """Defines the console layout."""
        layout = Layout(name="root")

        layout.split(
            Layout(name="header", size=3),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=7),
        )
        layout["main"].split_row(
            Layout(name="side"),
            Layout(name="body", ratio=2, minimum_size=60),
        )
        return layout

    def _get_external_id(self, attck_object) -> str:
        """Retrieves the official MITRE ID from an objects external references.

        Args:
            attck_object (Any): A MITRE ATTCK object type.

        Returns:
            str: The official designated MITRE ATT&CK ID.
        """
        if hasattr(attck_object, "external_references"):
            for item in getattr(attck_object, "external_references"):
                if (
                    hasattr(item, "external_id")
                    and getattr(item, "external_id")
                    and not getattr(item, "external_id").startswith("CAPEC")
                ):
                    return getattr(item, "external_id")

    def make_top_left_box(self):
        """Creates text string used in the Details section."""
        return f"""
[bold cyan1]ID: [/]{self._get_external_id(self.item)}
[bold cyan1]Revoked: [/]{self.item.revoked if hasattr(self.item, 'revoked') else 'False'}
[bold cyan1]Type: [/]{self.item.type}
[bold cyan1]STIX: [/]{self.item.id}
[bold cyan1]Created: [/]{self.item.created}
[bold cyan1]Modified: [/]{self.item.modified}
"""

    def make_general_information(self) -> Panel:
        """Generates the Panel containing the general information section."""
        sponsor_message = Table.grid(padding=1)
        sponsor_message.add_column(style="green", justify="right")
        sponsor_message.add_column(no_wrap=True)

        for ref in self.item.external_references:
            if ref.url:
                sponsor_message.add_row(
                    f"{ref.source_name} - {ref.url} - {ref.description}",
                    f"[u blue link={ref.url}]",
                )

        if self.item.description:
            intro_message = Text.from_markup(self.item.description.replace("[", ""))
        else:
            intro_message = Text.from_markup("UNKNOWN")

        message = Table.grid(padding=1)
        message.add_column()
        message.add_column(no_wrap=True)
        message.add_row(intro_message, sponsor_message)

        message_panel = Panel(
            Align.center(
                Group(intro_message, "\n", Align.center(sponsor_message)),
                vertical="middle",
            ),
            box=box.ROUNDED,
            padding=(1, 2),
            title="[b red]General Information",
            border_style="bright_blue",
        )
        return message_panel
