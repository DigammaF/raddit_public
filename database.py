
import math
import queue
import sqlite3
import threading
import weakref
from datetime import datetime, timedelta
from json import dumps, loads
from pathlib import Path
from random import choice
from string import ascii_lowercase, ascii_uppercase, digits
from typing import Any, Iterable, Optional

import Levenshtein  # type: ignore
from rich.console import Console

from email_verification import EmailVerification
from herald import Herald
from locator import Locator
from notification import Notification
from post import Post
from private_message import PrivateMessage
from protocols import (EmailVerificationProtocol, Key, NotificationProtocol,
                       PostProtocol, PrivateMessageProtocol, SubradditProtocol,
                       UserProtocol)
from raddit_event import *
from subraddit import Subraddit, SubradditPostPolicy
from user import User

KEYCHARS = digits + ascii_lowercase + ascii_uppercase

# datetime.timestamp() datetime.fromtimestamp()

def make_new_database(file: Path):
	
	connector = sqlite3.connect(file)
	cursor = connector.cursor()

	cursor.execute("""
		CREATE TABLE private_messages (
			text text,
			read integer,
			author text,
			timestamp real,
			key text
		)
	""")
	cursor.execute("""
		CREATE TABLE posts (
			author text,
			text text,
			title text,
			children text,
			parent text,
			timestamp real,
			subscribers text,
			key text
		)
	""")
	cursor.execute("""
		CREATE TABLE subraddits (
			name text,
			owner text,
			key text,
			posts text,
			post_policy text,
			whitelist text,
			blacklist text,
			description text
		)
	""")
	cursor.execute("""
		CREATE TABLE users (
			name text,
			email text,
			email_verified integer,
			password_hash text,
			posts text,
			private_messages_whitelist text,
			private_messages text,
			notifications text,
			owned_subraddits text,
			key text
		)
	""")
	cursor.execute("""
		CREATE TABLE email_verifications (
			target text,
			key text,
			timestamp real
		)
	""")
	cursor.execute("""
		CREATE TABLE notifications (
			target text,
			text text,
			title text,
			read integer,
			link text,
			key text
		)
	""")
	cursor.execute("""
		CREATE TABLE keys (
			data text
		)
	""")

	connector.commit()
	cursor.close()
	connector.close()

class StaticCache:

	events: Herald[CacheEvent] = Herald()
	cache: dict[str, Any] = {}

	@staticmethod
	def set(k, obj):

		StaticCache.events.dispatch(CacheInfo(text=f"setting {k} -> {obj}"))

		if obj is None:

			try:
				StaticCache.cache.pop(k)

			except KeyError:
				pass

		else:
			StaticCache.cache[k] = weakref.ref(obj)

def cached(f):

	def tmp(self, k, *args, **kwargs):

		StaticCache.events.dispatch(CacheInfo(text=f"querrying {k}"))
		ref = StaticCache.cache.get(k, None)

		if ref is None or (obj := ref()) is None:

			obj = f(self, k, *args, **kwargs)
			StaticCache.set(k, obj)
		
		return obj

	return tmp

SQLTask = tuple[str, dict, Optional[queue.Queue[list]]]
# sql, params, add a queue if you need the result of fetchall

class SQLiteWorker(threading.Thread):

	def __init__(self, file: Path):

		super().__init__()
		self.setDaemon(False)
		self.events: Herald[SQLEvent] = Herald()
		if not file.exists(): make_new_database(file)
		self._tasks: queue.Queue[SQLTask] = queue.Queue()
		self._keep_going = True
		self._task_count = 0
		self._connector = sqlite3.connect(file, check_same_thread=False)
		self._cursor = self._connector.cursor()
		self._console = Console()

	def stop(self):

		self.events.dispatch(SQLInfo(text="got order to stop"))
		self._keep_going = False

	def close(self):

		self._cursor.close()
		self._connector.close()
		self.events.dispatch(SQLInfo(text="closed connection"))

	def put_task(self, task: SQLTask):

		self.events.dispatch(SQLInfo(text=f"got task {task}"))
		self._tasks.put(task)
		self._task_count += 1
		self.events.dispatch(SQLChargeInfo(pending_task_count=self._task_count))

	def run(self):

		self.events.dispatch(SQLInfo(text="started SQL worker"))

		while self._keep_going:

			try:
				sql, params, result = self._tasks.get(block=True, timeout=1)

			except queue.Empty:
				continue

			self._task_count -= 1
			self.events.dispatch(SQLInfo(text=f"working on {(sql, params)}"))

			try:
				self._cursor.execute(sql, params)
				self._connector.commit()

			except Exception:

				self.events.dispatch(SQLError(text="error in SQL worker"))
				self._console.print_exception(show_locals=True)
				continue

			if result is not None:

				ans = list(self._cursor.fetchall())
				result.put(ans)
				self.events.dispatch(SQLInfo(text=f"answered {ans}"))

class AtomicOp:

	events: Herald[LockEvent] = Herald()

	def __init__(self, lock: threading.Lock) -> None:

		self._lock = lock

	def __enter__(self):

		self.events.dispatch(LockInfo(text=f"acquiring {id(self._lock)}"))
		self._lock.acquire()

	def __exit__(self, *args, **kwargs):

		self.events.dispatch(LockInfo(text=f"releasing {id(self._lock)}"))
		self._lock.release()

class Database:

	def __init__(self, file: Path) -> None:

		if not file.exists(): make_new_database(file)
		self.events: Herald[DBEvent] = Herald()
		self._file = file
		self._keys: set[Key] = set()
		self._lock = threading.Lock()
		self._sql_worker: SQLiteWorker = SQLiteWorker(file=self._file)

	def start(self):

		StaticCache.events.add(Locator.main)
		self.events.add(Locator.main)
		self._sql_worker.events.add(Locator.main)
		AtomicOp.events.add(Locator.main)
		self._sql_worker.start()

	def _execute(self, sql: str, params: dict = {}):

		self.events.dispatch(DBInfo(text=f"putting exec task {(sql, params)}"))
		self._sql_worker.put_task((sql, params, None))

	def _fetch(self, sql: str, params: dict = {}) -> Optional[list]:

		self.events.dispatch(DBInfo(text=f"putting fetch task {(sql, params)}"))
		ans_q: queue.Queue[list] = queue.Queue()
		self._sql_worker.put_task((sql, params, ans_q))

		try:
			ans = ans_q.get(block=True, timeout=10)

		except queue.Empty:

			self.events.dispatch(DBError(text=f"timed out at {(sql, params)}"))
			ans = None

		self.events.dispatch(DBInfo(text=f"got answer {ans}"))
		return ans

	def _fetch_one(self, sql: str, params: dict = {}) -> Any:

		ans = self._fetch(sql, params)

		if ans: return ans[0]
		else: return None

	def get_post(self, key: Key) -> Optional[PostProtocol]:

		with AtomicOp(self._lock):
			return self._get_post(key)

	@cached
	def _get_post(self, key: Key) -> Optional[PostProtocol]:

		self.events.dispatch(DBInfo(f"retreiving post {key}"))
		ans = self._fetch_one("SELECT * FROM posts WHERE key = :key", {"key": key})
		if ans is None: return None
		author_name, text, title, children_json, parent_key, _timestamp, subscribers_keys_json, key = ans
		author = self._get_user(author_name) if author_name != "none" else None
		children = list(loads(children_json))
		parent = parent_key if parent_key != "none" else None
		timestamp = datetime.fromtimestamp(_timestamp)

		return Post(
			author=author,
			text=text,
			title=title,
			children=children,
			parent=parent,
			timestamp=timestamp,
			subscribers=set(loads(subscribers_keys_json)),
			key=key,
		)

	def _post_exists(self, key: Key) -> bool:
		return bool(self._fetch_one("SELECT key FROM posts WHERE key = :key", {"key": key}))

	def set_post(self, post: PostProtocol):

		with AtomicOp(self._lock):
			self._set_post(post)

	def _set_post(self, post: PostProtocol):

		self.events.dispatch(DBInfo(f"setting post {post.get_key()}"))
		if self._post_exists(post.get_key()): return
		StaticCache.set(post.get_key(), post)
		author = post.get_author()
		text = post.get_text()
		title = post.get_title()
		children_json = dumps(list(post.get_children()))

		if (parent := post.get_parent_key()) is None:
			parent = "none"

		timestamp = post.get_timestamp().timestamp()
		subscribers_json = dumps(list(post.get_subscribers()))
		key = post.get_key()

		self._execute(
			"INSERT INTO posts VALUES("
			":author,"
			":text,"
			":title,"
			":children,"
			":parent,"
			":timestamp,"
			":subscribers,"
			":key"
			")",
			{
				"author": author.get_name() if author is not None else "none",
				"text": text,
				"title": title,
				"children": children_json,
				"parent": parent,
				"timestamp": timestamp,
				"subscribers": subscribers_json,
				"key": key,
			}
		)

	def get_email_verification(self, key: Key) -> Optional[EmailVerificationProtocol]:

		with AtomicOp(self._lock):
			return self._get_email_verification(key)

	@cached
	def _get_email_verification(self, key: Key) -> Optional[EmailVerificationProtocol]:

		self.events.dispatch(DBInfo(f"retreiving email verification {key}"))
		ans = self._fetch_one("SELECT * FROM email_verifications WHERE key = :key", {"key": key})

		if ans is None: return None
		target_name, key, _timestamp = ans
		target = self._get_user(target_name)

		if target is None:
			self.events.dispatch(DBError(text=f"failed to find target user {target_name} of email_verification {key}"))
			return None

		timestamp = datetime.fromtimestamp(_timestamp)
		return EmailVerification(target=target, key=key, timestamp=timestamp)

	def set_email_verification(self, email_verification: EmailVerificationProtocol):

		with AtomicOp(self._lock):
			self._set_email_verification(email_verification)

	def _set_email_verification(self, email_verification: EmailVerificationProtocol):

		self.events.dispatch(DBInfo(text=f"setting email_verification {email_verification.get_key()}"))
		StaticCache.set(email_verification.get_key(), email_verification)
		target_name = email_verification.get_target().get_name()
		key = email_verification.get_key()
		timestamp = email_verification.get_timestamp().timestamp()
		
		self._execute(
			"INSERT INTO email_verifications VALUES(:target_name, :key, :timestamp)",
			{
				"target_name": target_name,
				"key": key,
				"timestamp": timestamp,
			},
		)

	def rem_email_verification(self, key: Key):

		self.events.dispatch(DBInfo(f"deleting email_verification {key}"))
		StaticCache.set(key, None)
		self._execute("DELETE FROM email_verifications WHERE key = :key", {"key": key})

	def get_user(self, name: str) -> Optional[UserProtocol]:

		with AtomicOp(self._lock):
			return self._get_user(name)

	@cached
	def _get_user(self, name: str) -> Optional[UserProtocol]:

		self.events.dispatch(DBInfo(f"retreiving user {name}"))
		ans = self._fetch_one("SELECT * FROM users WHERE name = :name", {"name": name})
		if ans is None: return None
		name, email, email_verified, pass_hash, posts_json, pmw_json, pm_json, notifications_json, owned_subs_json, key = ans
		return User(
			name=name,
			email=email,
			email_verified=bool(email_verified),
			password_hash=pass_hash,
			posts=list(str(e) for e in loads(posts_json)),
			private_messages_whitelist=set(str(e) for e in loads(pmw_json)),
			private_messages=list(str(e) for e in loads(pm_json)),
			notifications=list(str(e) for e in loads(notifications_json)),
			owned_subraddits=set(str(e) for e in loads(owned_subs_json)),
			key=key,
		)

	def set_user(self, user: UserProtocol):

		with AtomicOp(self._lock):
			self._set_user(user)

	def _set_user(self, user: UserProtocol):

		self.events.dispatch(DBInfo(f"setting user {user.get_name()}"))
		StaticCache.set(user.get_name(), user)
		sql, params = (
			"INSERT INTO users VALUES("
			":name, :email, :email_verified, :password_hash, :posts, :private_messages_whitelist,"
			":private_messages, :notifications, :owned_subraddits,"
			":key"
			")",
			{
				"name": user.get_name(),
				"email": user.get_email(),
				"email_verified": int(user.is_email_verified()),
				"password_hash": user.get_password_hash(),
				"posts": dumps(list(user.get_posts())),
				"private_messages_whitelist": dumps(list(user.get_private_messages_whitelist())),
				"private_messages": dumps(list(user.get_private_messages())),
				"notifications": dumps(list(user.get_notifications())),
				"owned_subraddits": dumps(list(user.get_owned_subraddits())),
				"key": user.get_key(),
			},
		)

		self._execute(sql, params)

	def rem_user(self, name: str):

		self.events.dispatch(DBInfo(text=f"deleting user {name}"))
		StaticCache.set(name, None)
		self._execute("DEELET FROM users WHERE name = :name", {"name": name})
		self._execute("DELETE FROM notifications WHERE target = :name", {"name": name})

	def shadow_rem_user(self, name: str):

		self.events.dispatch(DBInfo(text=f"shadow deleting user {name}"))
		StaticCache.set(name, None)
		self._execute("UPDATE users SET password_hash = '' WHERE name = :name", {"name": name})
		self._execute("DELETE FROM notifications WHERE target = :name", {"name": name})

	def get_subraddit(self, key: Key) -> Optional[SubradditProtocol]:

		with AtomicOp(self._lock):
			return self._get_subraddit(key)

	@cached
	def _get_subraddit(self, key: Key) -> Optional[SubradditProtocol]:

		self.events.dispatch(DBInfo(text=f"retreiving subraddit {key}"))
		ans = self._fetch_one("SELECT * FROM subraddits WHERE key = :key", {"key": key})
		if ans is None: return None
		name, owner_name, key, posts_json, post_policy, whitelist_json, blacklist_json, description = ans
		owner = self._get_user(owner_name) if owner_name != "none" else None

		return Subraddit(
			name=name, owner=owner, key=key, posts=list(loads(posts_json)),
			post_policy=SubradditPostPolicy.load(post_policy),
			whitelist=set(loads(whitelist_json)), blacklist=set(loads(blacklist_json)),
			description=description,
		)

	def set_subraddit(self, subraddit: SubradditProtocol):

		with AtomicOp(self._lock):
			self._set_subraddit(subraddit)

	def _set_subraddit(self, subraddit: SubradditProtocol):

		self.events.dispatch(DBInfo(text=f"setting subraddit {subraddit.get_key()}"))
		owner = subraddit.get_owner()
		self._execute(
			"INSERT INTO subraddits VALUES("
			":name, :owner, :key, :posts, :post_policy, :whitelist, :blacklist, :description"
			")",
			{
				"name": subraddit.get_name(), "owner": owner.get_name() if owner is not None else "none",
				"key": subraddit.get_key(), "posts": dumps(list(subraddit.get_posts())),
				"post_policy": SubradditPostPolicy.save(subraddit.get_post_policy()),
				"whitelist": dumps(list(subraddit.get_whitelist())),
				"blacklist": dumps(list(subraddit.get_blacklist())),
				"description": subraddit.get_description(),
			},
		)

	def is_email_used(self, email: str) -> bool:
		return bool(self._fetch_one("SELECT email FROM users WHERE email = :email", {"email": email}))

	def clean_email_verifications(self):

		with AtomicOp(self._lock):
			self._clean_email_verifications()

	def _clean_email_verifications(self):

		self.events.dispatch(DBInfo(text=f"cleaning email verifications"))
		keys = self._fetch("SELECT key FROM email_verifications")
		# keys is a list of length one tuples
		delay = timedelta(minutes=15)
		now = datetime.now()

		for (key,) in keys:

			email_verification: Optional[EmailVerificationProtocol] = self._get_email_verification(key)

			if email_verification is None:
				self.events.dispatch(DBError(text=f"failed to find email verification {key}"))
				continue

			if (now - email_verification.get_timestamp()) > delay:

				email_verification.get_target().delete()
				self.rem_email_verification(key)

	def get_notification(self, key: Key) -> Optional[NotificationProtocol]:

		with AtomicOp(self._lock):
			return self._get_notification(key)

	@cached
	def _get_notification(self, key: Key) -> Optional[NotificationProtocol]:

		self.events.dispatch(DBInfo(text=f"retreiving notification {key}"))
		ans = self._fetch_one("SELECT * FROM notifications WHERE key = :key", {"key": key})
		if ans is None: return None
		target_name, text, title, read_txt, link, key = ans
		target = self._get_user(target_name)

		if target is None: 

			self.events.dispatch(DBError(text=f"Cannot find target {target_name} of notification {key}"))
			return None

		return Notification(
			target=target_name, text=text, title=title, read=bool(read_txt), link=link, key=key,
		)

	def set_notification(self, notification: NotificationProtocol):

		with AtomicOp(self._lock):
			self._set_notification(notification)

	def _set_notification(self, notification: NotificationProtocol):

		self.events.dispatch(DBInfo(text=f"setting notification {notification.get_key()}"))
		self._execute(
			"INSERT INTO notifications VALUES("
			":target, :text, :title, :read, :link, :key"
			")",
			{
				"target": notification.get_target().get_name(),
				"text": notification.get_text(),
				"title": notification.get_title(),
				"read": int(notification.get_read()),
				"link": notification.get_link(),
				"key": notification.get_key(),
			}
		)

	def rem_notification(self, key: Key):

		self.events.dispatch(DBInfo(text=f"deleting notification {key}"))
		StaticCache.set(key, None)
		self._execute("DELETE FROM notifications WHERE key = :key", {"key": key})

	def get_private_message(self, key: Key) -> Optional[PrivateMessageProtocol]:

		with AtomicOp(self._lock):
			return self._get_private_message()

	@cached
	def _get_private_message(self, key: Key) -> Optional[PrivateMessageProtocol]:

		self.events.dispatch(DBInfo(text=f"retreiving private message {key}"))
		ans = self._fetch_one("SELECT * FROM private_messages WHERE key = :key", {"key": key})
		if ans is None: return None
		text, read_txt, author, _timestamp, key = ans
		return PrivateMessage(
			text=text, read=bool(read_txt), author = author if author != "none" else None,
			timestamp=datetime.fromtimestamp(_timestamp), key=key,
		)

	def set_private_message(self, private_message: PrivateMessageProtocol):

		with AtomicOp(self._lock):
			self._set_private_message(private_message)

	def _set_private_message(self, private_message: PrivateMessageProtocol):

		self.events.dispatch(DBInfo(text=f"setting private message {private_message.get_key()}"))
		author = private_message.get_author()
		self._execute(
			"INSERT INTO private_messages VALUES("
			":text, :read, :author, :timestamp, :key"
			")",
			{
				"text": private_message.get_text(), "read": private_message.get_read(),
				"author": author if author is not None else "none",
				"timestamp": private_message.get_timestamp().timestamp(),
				"key": private_message.get_key()
			}
		)

	def get_new_key(self) -> Key:

		with AtomicOp(self._lock):
			return self._get_new_key()
	
	def _get_new_key(self) -> Key:

		while (key := "".join(choice(KEYCHARS) for _ in range(20))) in self._keys:
			continue

		self._keys.add(key)
		self._execute("INSERT INTO keys VALUES(:key)", {"key": key})
		return key

	def let_key(self, key: Key):

		self._keys.remove(key)
		self._execute("DELETE FROM keys WHERE data = :key", {"key": key})

	def exit(self):

		self.events.dispatch(DBInfo(text="exiting"))
		self._sql_worker.stop()
		self._sql_worker.join()
		self._sql_worker.close()

	def search_subraddit(self, name: str) -> Optional[tuple[str, Key]]:

		t, d = None, math.inf
		ans = self._fetch("SELECT name, key FROM subraddits")

		if ans is None: return None

		for l_name, key in ans:
			if (ld := Levenshtein.distance(l_name, name)) < d:
				t, d = (l_name, key), ld

		return t

	def subraddit_name_taken(self, name: str) -> bool:
		return bool(self._fetch(
			"SELECT name FROM subraddits WHERE name = :name",
			{
				"name": name,
			}
		))

	def post_update_children(self, post: PostProtocol):

		self.events.dispatch(DBInfo(text=f"updating children of {post.get_key()}"))
		self._execute(
			"UPDATE posts SET children = :children WHERE key = :key",
			{
				"children": dumps(list(post.get_children())),
				"key": post.get_key(),
			},
		)

	def post_update_subscribers(self, post: PostProtocol):

		self.events.dispatch(DBInfo(text=f"updating subscribers of {post.get_key()}"))
		self._execute(
			"UPDATE posts SET subscribers = :subscribers WHERE key = :key",
			{
				"subscribers": dumps([e for e in post.get_subscribers()]),
				"key": post.get_key(),
			}
		)

	def user_update_email_verified(self, user: UserProtocol):

		self.events.dispatch(DBInfo(text=f"updating email_verified of {user.get_name()} to {user.is_email_verified()}"))
		self._execute(
			"UPDATE users SET email_verified = :val WHERE name = :name",
			{"val": int(user.is_email_verified()), "name": user.get_name()}
		)

	def user_update_private_messages(self, user: UserProtocol):

		self.events.dispatch(DBInfo(text=f"updating private messages of {user.get_name()}"))
		self._execute(
			"UPDATE users SET private_messages = :val WHERE name = :name",
			{"val": dumps(list(user.get_private_messages())), "key": user.get_key()}
		)

	def user_update_password_hash(self, user: UserProtocol):

		self.events.dispatch(DBInfo(text=f"updating password hash of {user.get_name()} to {user.get_password_hash()}"))
		self._execute(
			"UPDATE users SET password_hash = :val WHERE name = :name",
			{
				"password_hash": user.get_password_hash(),
				"name": user.get_name(),
			}
		)

	def user_update_pmw(self, user: UserProtocol):

		self.events.dispatch(DBInfo(text=f"updating pmw of {user.get_name()}"))
		self._execute(
			"UPDATE users SET private_messages_whitelist = :val WHERE name = :name",
			{
				"val": dumps(list(user.get_private_messages_whitelist())),
				"name": user.get_name(),
			}
		)

	def user_update_owned_subraddits(self, user: UserProtocol):

		self.events.dispatch(DBInfo(text=f"updating owned subraddits of {user.get_name()}"))
		self._execute(
			"UPDATE users SET owned_subraddits = :val WHERE name = :name",
			{
				"val": dumps(list(user.get_owned_subraddits())),
				"name": user.get_name(),
			}
		)

	def user_get_unread_notification_count(self, user: UserProtocol) -> int:
		
		l = self._fetch(
			"SELECT key FROM notifications WHERE read = 0 AND target = :name",
			{
				"name": user.get_name(),
			}
		)
		if l is None: return 999
		return len(l)

	def user_get_notifications(self, user: UserProtocol) -> Iterable[Key]:

		l = self._fetch("SELECT key FROM notifications WHERE target = :name", {"name": user.get_name()})

		if l is None: return

		for (key,) in l:
			yield key

	def subraddit_update_post_policy(self, subraddit: SubradditProtocol):

		self.events.dispatch(DBInfo(text=f"updating post policy of subraddit {subraddit.get_key()} to {subraddit.get_post_policy()}"))
		self._execute(
			"UPDATE subraddits SET post_policy = :val WHERE key = :key",
			{
				"val": SubradditPostPolicy.save(subraddit.get_post_policy()),
				"key": subraddit.get_key(),
			}
		)

	def subraddit_update_whitelist(self, subraddit: SubradditProtocol):

		self.events.dispatch(DBInfo(text=f"updating whitelist of subraddit {subraddit.get_key()}"))
		self._execute(
			"UPDATE subraddits SET whitelist = :whitelist WHERE key = :key",
			{
				"whitelist": dumps(list(subraddit.get_whitelist())),
				"key": subraddit.get_key(),
			}
		)

	def subraddit_update_blacklist(self, subraddit: SubradditProtocol):

		self.events.dispatch(DBInfo(text=f"updating blacklist of subraddit {subraddit.get_key()}"))
		self._execute(
			"UPDATE subraddits SET blacklist = :blacklist WHERE key = :key",
			{
				"blacklist": dumps(list(subraddit.get_blacklist())),
				"key": subraddit.get_key(),
			}
		)

	def subraddit_update_posts(self, subraddit: SubradditProtocol):

		self.events.dispatch(DBInfo(text=f"updating posts of subraddit {subraddit.get_key()}"))
		self._execute(
			"UPDATE subraddits SET posts = :posts WHERE key = :key",
			{
				"posts": dumps(list(subraddit.get_posts())),
				"key": subraddit.get_key(),
			}
		)

	def subraddit_update_description(self, subraddit: SubradditProtocol):

		self.events.dispatch(DBInfo(text=f"updating description of subraddit {subraddit.get_key()}"))
		self._execute(
			"UPDATE subraddits SET description = :val WHERE key = :key",
			{
				"val": subraddit.get_description(),
				"key": subraddit.get_key(),
			}
		)

	def notification_update_read(self, notification: NotificationProtocol):

		self.events.dispatch(DBInfo(text=f"updating read status of notification {notification.get_key()} to {notification.get_read()}"))
		self._execute(
			"UPDATE notifications SET read = :read WHERE key = :key",
			{
				"read": int(notification.get_read()),
				"key": notification.get_key(),
			}
		)

	def private_message_update_read(self, private_message: PrivateMessageProtocol):

		self.events.dispatch(DBInfo(text=f"updating read status of private message {private_message.get_key()} to {private_message.get_read()}"))
		self._execute(
			"UPDATE private_messages SET read = :read WHERE key = :key",
			{
				"read": int(private_message.get_read()),
				"key": private_message.get_key(),
			}
		)
