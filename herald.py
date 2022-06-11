
from typing import TypeVar, Generic, Protocol

T = TypeVar("T", contravariant=True)

class ObserverProtocol(Protocol, Generic[T]):

	def on_event(self, event: T): pass

class Herald(Generic[T]):

	def __init__(self):

		self._observers: list[ObserverProtocol[T]] = []

	def add(self, observer: ObserverProtocol[T]):
		self._observers.append(observer)

	def rem(self, observer: ObserverProtocol[T]):
		self._observers.remove(observer)

	def dispatch(self, event: T):

		for observer in self._observers:
			observer.on_event(event)
