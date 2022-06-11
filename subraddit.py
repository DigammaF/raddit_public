
from __future__ import annotations
from typing import Iterable, Optional
from protocols import UserProtocol, PostProtocol, Key, SubradditPostPolicyAbc
from keyed import Keyed
from locator import Locator

class SubradditPostPolicy(SubradditPostPolicyAbc):

	free_for_all = "free for all"
	whitelist = "whitelist"
	blacklist = "blacklist"

	@staticmethod
	def save(e: SubradditPostPolicy) -> str:
		return e.value

	@staticmethod
	def load(text: str) -> SubradditPostPolicy:
		return {e.value: e for e in SubradditPostPolicy}[text]

class Subraddit(Keyed):

	def __init__(self,
		name: str,
		owner: Optional[UserProtocol],
		key: Key,
		posts: list[Key],
		post_policy: SubradditPostPolicy,
		whitelist: set[Key],
		blacklist: set[Key],
		description: str,
	):

		Keyed.__init__(self, key)
		self._name = name
		self._owner = owner
		self._posts: list[Key] = posts
		self._post_policy: SubradditPostPolicy = post_policy
		self._whitelist: set[Key] = whitelist
		self._blacklist: set[Key] = blacklist
		self._description: str = description

	@classmethod
	def new(cls, name: str, owner: UserProtocol, description: str) -> Subraddit:
		return Subraddit(
			name=name,
			owner=owner,
			key=Locator.main.database.get_new_key(),
			posts=[],
			post_policy=SubradditPostPolicy.free_for_all,
			whitelist=set(),
			blacklist=set(),
			description=description,
		)

	def add_post(self, post: PostProtocol):

		self._posts.append(post.get_key())
		Locator.main.database.subraddit_update_posts(self)

	def get_posts(self) -> Iterable[Key]:
		return self._posts

	def get_name(self) -> str:
		return self._name

	def get_owner(self) -> Optional[UserProtocol]:
		return self._owner

	def is_whitelisted(self, user: UserProtocol) -> bool:
		return user.get_name() in self._whitelist

	def is_blacklisted(self, user: UserProtocol) -> bool:
		return user.get_name() in self._blacklist

	def get_post_policy(self) -> SubradditPostPolicy:
		return self._post_policy

	def set_post_policy(self, p: SubradditPostPolicy):
		
		self._post_policy = p
		Locator.main.database.subraddit_update_post_policy(self)

	def get_whitelist(self) -> Iterable[str]:
		return (e for e in self._whitelist)

	def get_blacklist(self) -> Iterable[str]:
		return (e for e in self._blacklist)

	def add_whitelist(self, user: UserProtocol):

		self._whitelist.add(user.get_name())
		Locator.main.database.subraddit_update_whitelist(self)

	def rem_whitelist(self, user: UserProtocol):

		self._whitelist.remove(user.get_name())
		Locator.main.database.subraddit_update_whitelist(self)

	def add_blacklist(self, user: UserProtocol):

		self._blacklist.add(user.get_name())
		Locator.main.database.subraddit_update_blacklist(self)

	def rem_blacklist(self, user: UserProtocol):

		self._blacklist.remove(user.get_name())
		Locator.main.database.subraddit_update_blacklist(self)

	def comply_with_post_policy(self, user: UserProtocol) -> bool:

		if self._post_policy is SubradditPostPolicy.free_for_all:
			return True

		elif self._post_policy is SubradditPostPolicy.whitelist:
			return user.get_name() in self._whitelist

		elif self._post_policy is SubradditPostPolicy.blacklist:
			return user.get_name() not in self._blacklist

		else:
			return False

	def get_description(self) -> str:
		return self._description

	def set_description(self, text: str):
		
		self._description = text
		Locator.main.database.subraddit_update_description(self)

	def clean_post_policy(self):

		changed: bool = False
		to_rem: list[str] = []

		for name in self._whitelist:

			if Locator.main.database.get_user(name) is None:

				changed = True
				to_rem.append(name)

		for name in to_rem:
			self._whitelist.remove(name)

		to_rem: list[str] = []
		
		for name in self._blacklist:

			if Locator.main.database.get_user(name) is None:

				changed = True
				to_rem.append(name)

		for name in to_rem:
			self._blacklist.remove(name)

		if changed:
			Locator.main.database.subraddit_update_whitelist(self)
			Locator.main.database.subraddit_update_blacklist(self)
