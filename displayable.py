
class Displayable:

	def __init__(self, text: str, title: str):

		self._text = text
		self._title = title

	def get_title(self) -> str:
		return self._title

	def get_text(self) -> str:
		return self._text
