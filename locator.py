
from __future__ import annotations
from timer import Timer
from datetime import datetime
from random import choice
from string import ascii_lowercase
from rich.console import Console
from raddit_email import MailSender
from protocols import DatabaseProtocol
from pathlib import Path
from raddit_event import ActionEvent, Event, Error

class Locator:

	main: Locator = None # type: ignore

	def __init__(self, database: DatabaseProtocol, log_dir: Path) -> None:

		self.database: DatabaseProtocol = database
		self.timers: dict[str, Timer] = {}
		self.mail_sender: MailSender = MailSender()
		self.domain: str = "no domain set"
		self._log_dir: Path = log_dir
		self._logs: Console = Console(record=True, soft_wrap=True)

	def __enter__(self):

		pass

	def __exit__(self, *args, **kwargs):

		self.exit()

	def start(self):

		self.bind_main()
		self.database.start()

	def exit(self):

		self.print_log("[bold red] Shutting down locator")
		self.database.exit()
		self.mail_sender.exit()
		self.output_logs()

	def bind_main(self):

		self.__class__.main = self

	def output_logs(self):

		stem = "".join(choice(ascii_lowercase) for _ in range(50))
		self._logs.save_html(self._log_dir/f"{stem}.html")

	def print_log(self, text: str):

		self._logs.print(f"[dim]{datetime.now()}...[/dim]{text}")

	def on_event(self, event: Event):
		
		if isinstance(event, Error):
			style = "red"

		elif isinstance(event, ActionEvent):
			style = "bold purple"

		else:
			style = "normal"

		self.print_log(f"[{style}]{event}[/{style}]")
