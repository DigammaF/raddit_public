
from datetime import timedelta, datetime, MINYEAR

class Timer:

	def __init__(self, interval: timedelta):

		self._interval: timedelta = interval
		self._last_check: datetime = datetime(year=MINYEAR, month=1, day=1)

	def check(self, time: datetime) -> bool:

		if (time - self._last_check) > self._interval:

			self._last_check = time
			return True

		return False
