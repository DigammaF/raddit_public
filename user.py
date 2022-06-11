
from __future__ import annotations
from typing import Iterable
from keyed import Keyed
from protocols import PostProtocol, Key, PrivateMessageProtocol, NotificationProtocol, SubradditProtocol, UserProtocol
from locator import Locator

class User(Keyed):

	def __init__(self,
		name: str,
		email: str,
		email_verified: bool,
		password_hash: str,
		posts: list[Key],
		private_messages_whitelist: set[Key],
		private_messages: list[Key],
		notifications: list[Key],
		owned_subraddits: set[Key],
		key: Key,
	):

		Keyed.__init__(self, key)
		self._name: str = name
		self._email: str = email
		self._email_verified: bool = email_verified
		self._password_hash: str = password_hash
		self._posts: list[Key] = posts
		self._private_messages_whitelist: set[Key] = private_messages_whitelist
		self._private_messages: list[Key] = private_messages
		self._notifications: list[Key] = notifications
		self._owned_subraddits: set[Key] = owned_subraddits

	@staticmethod
	def new(name: str, email: str, password_hash: str) -> User:
		return User(
			name = name,
			email = email,
			email_verified = False,
			password_hash = password_hash,
			posts = [],
			private_messages_whitelist = set(),
			private_messages = [],
			notifications = [],
			owned_subraddits = set(),
			key = Locator.main.database.get_new_key(),
		)

	def get_name(self) -> str:
		return self._name

	def get_email(self) -> str:
		return self._email

	def is_email_verified(self) -> bool:
		return self._email_verified

	def set_email_verified(self, v: bool):

		self._email_verified = v
		Locator.main.database.user_update_email_verified(self)

	def add_private_message(self, key: Key):

		self._private_messages.append(key)
		Locator.main.database.user_update_private_messages(self)

	def get_password_hash(self) -> str:
		return self._password_hash

	def get_posts(self) -> Iterable[Key]:
		return self._posts

	def get_private_messages_whitelist(self) -> set[Key]:
		return self._private_messages_whitelist

	def add_pmw(self, name: str):

		self._private_messages_whitelist.add(name)
		Locator.main.database.user_update_pmw(self)

	def rem_pmw(self, name: str):

		self._private_messages_whitelist.remove(name)
		Locator.main.database.user_update_pmw(self)

	def get_private_messages(self) -> Iterable[Key]:
		return self._private_messages

	def get_notifications(self) -> Iterable[Key]:
		return Locator.main.database.user_get_notifications(self)

	def get_owned_subraddits(self) -> Iterable[Key]:
		return self._owned_subraddits

	def set_password_hash(self, password_hash: str):

		self._password_hash = password_hash
		Locator.main.database.user_update_password_hash(self)

	def delete(self):

		Locator.main.database.rem_user(self._name)

	def shadow_delete(self):

		Locator.main.database.shadow_rem_user(self._name)
		self._password_hash = ""

	def own_subraddit(self, key: Key) -> bool:
		return key in self._owned_subraddits

	def add_owned_subraddit(self, key: Key):

		self._owned_subraddits.add(key)
		Locator.main.database.user_update_owned_subraddits(self)

	def get_unread_notifications_count(self) -> int:
		return Locator.main.database.user_get_unread_notification_count(self)

	def is_deleted(self) -> bool:
		return self._password_hash == ""
