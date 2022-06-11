
from __future__ import annotations
from dataclasses import dataclass

class Event:
	pass

class Error(Event):
	pass

class SQLEvent(Event):
	pass

@dataclass
class SQLInfo(SQLEvent):
	
	text: str

@dataclass
class SQLChargeInfo(SQLEvent):

	pending_task_count: int

@dataclass
class SQLError(Error):

	text: str

class DBEvent(Event):
	pass

@dataclass
class DBError(DBEvent, Error):

	text: str

@dataclass
class DBInfo(DBEvent):

	text: str

class CacheEvent(Event):
	pass

@dataclass
class CacheInfo(CacheEvent):

	text: str

class LockEvent(Event):
	pass

@dataclass
class LockInfo(LockEvent):
	
	text: str

class ActionEvent(Event):
	pass

@dataclass
class ActionInfo(ActionEvent):

	text: str

@dataclass
class ActionError(ActionEvent, Error):

	text: str
