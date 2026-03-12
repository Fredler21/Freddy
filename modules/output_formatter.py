"""Output Formatter Module — formats Freddy reports with Rich."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.syntax import Syntax


class OutputFormatter:
    """Formats Freddy analysis output with Rich for terminal display."""

    def __init__(self):
        self.console = Console()

    def print_banner(self, title: str = "FREDDY — Cyber Intelligence Report"):
        """Print the Freddy banner."""
        banner = Text(title, style="bold cyan")
        self.console.print(Panel(banner, border_style="cyan", padding=(0, 2)))

    def print_section(
        self,
        title: str,
        content: str,
        style: str = "green",
    ):
        """Print a formatted section."""
        self.console.print()
        self.console.print(
            Panel(
                content,
                title=f"[bold {style}]{title}[/bold {style}]",
                border_style=style,
                padding=(1, 2),
            )
        )

    def print_error(self, message: str):
        """Print an error message."""
        self.console.print()
        self.console.print(
            Panel(
                f"[bold red]ERROR[/bold red]\n{message}",
                border_style="red",
                padding=(1, 2),
            )
        )

    def print_warning(self, message: str):
        """Print a warning message."""
        self.console.print()
        self.console.print(
            Panel(
                f"[bold yellow]WARNING[/bold yellow]\n{message}",
                border_style="yellow",
                padding=(1, 2),
            )
        )

    def print_info(self, message: str):
        """Print an info message."""
        self.console.print(f"[bold cyan]ℹ  {message}[/bold cyan]")

    def print_success(self, message: str):
        """Print a success message."""
        self.console.print(f"[bold green]✓ {message}[/bold green]")

    def print_failure(self, message: str):
        """Print a failure message."""
        self.console.print(f"[bold red]✗ {message}[/bold red]")

    def print_analysis(
        self,
        analysis: str,
        knowledge_applied: bool = False,
        rule_finding_count: int = 0,
    ):
        """Print the AI analysis as the main report."""
        self.console.print()
        self.print_banner()
        if knowledge_applied:
            self.console.print("[bold green]Knowledge context applied[/bold green]")
        if rule_finding_count:
            self.console.print(
                f"[bold yellow]Rule findings generated:[/bold yellow] {rule_finding_count}"
            )
        self.console.print()
        self.print_section("Analysis", analysis)
        self.console.print()

    def print_code(self, code: str, language: str = "bash", title: str = ""):
        """Print code with syntax highlighting."""
        syntax = Syntax(code, language, theme="monokai", line_numbers=False)
        if title:
            self.console.print(Panel(syntax, title=f"[bold]{title}[/bold]"))
        else:
            self.console.print(syntax)

    def print_table(self, rows: list, headers: list, title: str = ""):
        """Print a formatted table."""
        table = Table(title=title, show_header=True, header_style="bold cyan")
        for header in headers:
            table.add_column(header)
        for row in rows:
            table.add_row(*row)
        self.console.print(table)

    def print_history_table(self, rows: list[tuple[str, str, str, str]], title: str):
        """Print scan history records."""
        table = Table(title=title, show_header=True, header_style="bold cyan")
        table.add_column("Timestamp")
        table.add_column("Target")
        table.add_column("Command")
        table.add_column("Severity")
        for row in rows:
            table.add_row(*row)
        self.console.print(table)

    def print_memory_stats(self, stats: object) -> None:
        """Print Freddy memory statistics."""
        self.console.print()
        self.console.print("[bold cyan]Freddy Memory Statistics[/bold cyan]\n")
        self.console.print(f"  Total scans stored : [bold]{stats.total_scans}[/bold]")
        self.console.print(f"  Unique targets     : [bold]{stats.unique_targets}[/bold]")
        if stats.recent_targets:
            self.console.print(f"  Recent targets     : {', '.join(stats.recent_targets[:5])}")
        if stats.top_vulnerabilities:
            self.console.print()
            table = Table(title="Most Frequent Findings", show_header=True, header_style="bold yellow")
            table.add_column("Finding", no_wrap=False)
            table.add_column("Count", justify="right")
            for finding, count in stats.top_vulnerabilities:
                table.add_row(finding[:80], str(count))
            self.console.print(table)
        self.console.print()
