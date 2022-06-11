
from protocols import Key

class Keyed:

	def __init__(self, key: Key):

		self._key = key

	def get_key(self) -> Key:
		return self._key
