
from __future__ import annotations
from typing import Iterable, Optional
from datetime import datetime
from displayable import Displayable
from keyed import Keyed
from protocols import Key, UserProtocol, PostProtocol
from locator import Locator

class Post(Displayable, Keyed):
	
	def __init__(self,
		author: Optional[UserProtocol],
		text: str,
		title: str,
		children: list[Key],
		parent: Optional[Key],
		timestamp: datetime,
		subscribers: set[str],
		key: Key,
	) -> None:
		
		Displayable.__init__(self, text=text, title=title)
		Keyed.__init__(self, key=key)

		self._author: Optional[UserProtocol] = author
		self._children: list[Key] = children
		self._parent: Optional[Key] = parent
		self._timestamp: datetime = timestamp
		self._subscribers: set[str] = subscribers

	@classmethod
	def new(cls, author: UserProtocol, text: str, title: str, parent: Optional[Key] = None) -> Post:
		return Post(
			author=author,
			text=text,
			title=title,
			children=[],
			parent=parent,
			timestamp=datetime.now(),
			subscribers=set(),
			key=Locator.main.database.get_new_key(),
		)

	def add_child(self, child: PostProtocol):

		self._children.append(child.get_key())
		Locator.main.database.post_update_children(self)

	def get_children(self) -> Iterable[Key]:
		return self._children

	def get_children_count(self) -> int:
		return len(self._children)

	def get_timestamp(self) -> datetime:
		return self._timestamp

	def get_parent_key(self) -> Optional[Key]:
		return self._parent

	def get_author(self) -> Optional[UserProtocol]:
		return self._author

	def subscribe(self, user: UserProtocol):

		self._subscribers.add(user.get_name())
		Locator.main.database.post_update_subscribers(self)

	def unsubscribe(self, user: UserProtocol):

		self._subscribers.remove(user.get_name())
		Locator.main.database.post_update_subscribers(self)

	def is_subscribed(self, user: UserProtocol) -> bool:
		return user.get_name() in self._subscribers

	def get_subscribers(self) -> Iterable[Key]:
		return (name for name in self._subscribers)

	def get_subscribers_count(self) -> int:
		return len(self._subscribers)
