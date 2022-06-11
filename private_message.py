
from __future__ import annotations
from typing import Optional
from displayable import Displayable
from keyed import Keyed
from locator import Locator
from protocols import Key
from datetime import datetime

class PrivateMessage(Displayable, Keyed):

	def __init__(self, text: str, read: bool, author: Optional[Key], timestamp: datetime, key: Key):

		Displayable.__init__(self, text, "")
		Keyed.__init__(self, key)
		self._read = read
		self._author = author
		self._timestamp = timestamp

	@staticmethod
	def new(author: Optional[Key], text) -> PrivateMessage:
		return PrivateMessage(
			text=text,
			read=False,
			author=author,
			timestamp=datetime.now(),
			key=Locator.main.database.get_new_key(),
		)

	def get_author(self) -> Optional[Key]:
		return self._author

	def get_read(self) -> bool:
		return self._read

	def set_read(self, v: bool):

		self._read = v
		Locator.main.database.private_message_update_read(self)

	def get_timestamp(self) -> datetime:
		return self._timestamp
