
from __future__ import annotations
from datetime import datetime
from keyed import Keyed
from protocols import UserProtocol, Key
from locator import Locator

class EmailVerification(Keyed):

	def __init__(self, target: UserProtocol, key: Key, timestamp: datetime):

		Keyed.__init__(self, key)
		self._target = target
		self._timestamp = timestamp

	@classmethod
	def new(cls, target: UserProtocol) -> EmailVerification:
		return EmailVerification(
			target=target,
			key=Locator.main.database.get_new_key(),
			timestamp=datetime.now(),
		)

	def get_target(self) -> UserProtocol:
		return self._target

	def get_timestamp(self) -> datetime:
		return self._timestamp

	def delete(self):
		Locator.main.database.rem_email_verification(self._key)
