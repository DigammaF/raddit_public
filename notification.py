
from __future__ import annotations
from keyed import Keyed
from displayable import Displayable
from protocols import Key, UserProtocol
from locator import Locator

class Notification(Keyed, Displayable):

	def __init__(self, target: UserProtocol, text: str, title: str, read: bool, link: str, key: Key):

		Keyed.__init__(self, key)
		Displayable.__init__(self, text, title)

		self._read = read
		self._target = target
		self._link = link

	@staticmethod
	def new(target: UserProtocol, text: str, title: str, link: str) -> Notification:
		return Notification(
			target=target, text=text, title=title, read=False, link=link, key=Locator.main.database.get_new_key(),
		)

	def get_read(self) -> bool:
		return self._read

	def set_read(self, v: bool):
		
		self._read = v
		Locator.main.database.notification_update_read(self)

	def get_target(self) -> UserProtocol:
		return self._target

	def get_link(self) -> str:
		return self._link
