
import smtplib
import email_login

from time import sleep

class MailError(Exception): pass
class TargetNotFound(MailError): pass

class UnknownError(MailError):

	def __init__(self, e):

		self.e = e

class MailSender:

	def __init__(self) -> None:
		
		self._server = smtplib.SMTP("smtp.gmail.com", 587)
		self._server.starttls()
		self._server.login(email_login.username, email_login.password)

	def send(self, target: str, message: str, attempts: int = 6):

		mail_text = (
			f"From: {email_login.username}\r\n"
			f"To: {target}\r\n\r\n"
			f"{message}"
		)

		try:
			self._server.sendmail(email_login.username, target, mail_text)

		except smtplib.SMTPRecipientsRefused:
			raise TargetNotFound()

		except smtplib.SMTPException as e:

			if attempts > 0:

				sleep(1)
				self.send(target=target, message=message, attempts = attempts - 1)

			else:
				raise UnknownError(e) from e

	def exit(self):
		self._server.quit()
