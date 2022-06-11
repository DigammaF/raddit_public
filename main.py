
import re
from datetime import datetime, timedelta
from io import StringIO
from pathlib import Path
from string import ascii_lowercase, ascii_uppercase, digits
from time import sleep
from typing import Literal, Optional

import flask
from flask import Flask, redirect, request, session
from flask_session import Session  # type: ignore
from rich.console import Console
from rich.markdown import Markdown
from rich.padding import Padding
from rich.panel import Panel
from rich.layout import Layout
from rich.traceback import install

import protocols
from database import Database
from email_verification import EmailVerification
from herald import Herald
from locator import Locator
from notification import Notification
from post import Post
from private_message import PrivateMessage
from raddit_event import ActionError, ActionEvent, ActionInfo
from subraddit import Subraddit, SubradditPostPolicy
from timer import Timer
from user import User
from raddit_email import UnknownError, TargetNotFound

# link: yellow

install(show_locals=True, suppress=[flask,])

ALLOWED_CHARS: set[str] = set(digits + ascii_lowercase + ascii_uppercase + r",.?!()^$€*/+-:; @_[]\\>#" + "\r\n" + "\"'")
NAME_ALLOWED_CHARS: set[str] = set(digits + ascii_lowercase + ascii_uppercase + r"_") # valid for username and subraddit name
EMAIL_REGEX = re.compile(r"^[\w\.]+@(protonmail.com|gmail.com)$")
INDENT_SIZE: int = 3
TITLE_MAX_CHARS: int = 100
POST_TEXT_MAX_CHARS: int = 1_000_000
NAME_MAX_CHARS: int = 30 # valid for username and subraddit name
SUB_DESC_MAX_CHARS: int = POST_TEXT_MAX_CHARS
PM_MAX_CHARS: int = POST_TEXT_MAX_CHARS
POST_REPLY_MAX_CHARS: int = 2000

app = Flask("raddit")
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

class Action:
	"""
	
		Arguments to those methods are supposed to be valid

	"""

	events: Herald[ActionEvent] = Herald()

	@staticmethod
	def get_session_user() -> Optional[protocols.UserProtocol]:
		return session.get("user") # type: ignore

	@staticmethod
	def cast_key(v: str) -> protocols.Key:
		return v #type: ignore

	@staticmethod
	def create_user(name: str, email: str, password: str) -> User:

		Action.events.dispatch(ActionInfo(text=f"creating user '{name}' '{email}'"))
		user = User.new(name=name, email=email, password_hash=protocols.hash(password))
		Locator.main.database.set_user(user)
		return user

	@staticmethod
	def create_email_verification(target: protocols.UserProtocol) -> EmailVerification:

		Action.events.dispatch(ActionInfo(text=f"creating email verification for '{target.get_name()}' '{target.get_email()}'"))
		email_verification = EmailVerification.new(target=target)
		Locator.main.database.set_email_verification(email_verification)
		return email_verification

	@staticmethod
	def send_mail(email_address: str, text: str):

		Action.events.dispatch(ActionInfo(text=f"sending an email at '{email_address}'"))

		try:
			Locator.main.mail_sender.send(email_address, text)

		except UnknownError as e:
			Action.events.dispatch(ActionError(text=f"failed to send mail because {e.e}"))

	@staticmethod
	def validate_email_address(email_verification: protocols.EmailVerificationProtocol):

		Action.events.dispatch(ActionInfo(text=f"validating email address of '{email_verification.get_target()}'"))
		target: protocols.UserProtocol = email_verification.get_target()
		target.set_email_verified(True)
		Locator.main.database.rem_email_verification(email_verification.get_key())

	@staticmethod
	def change_password(user: protocols.UserProtocol, password: str):

		Action.events.dispatch(ActionInfo(text=f"changing password of '{user.get_name()}'"))
		user.set_password_hash(protocols.hash(password))

	@staticmethod
	def delete_account(user: protocols.UserProtocol):

		Action.events.dispatch(ActionInfo(text=f"deleting account {user.get_name()}"))
		user.shadow_delete()

	@staticmethod
	def create_subraddit(name: str, owner: protocols.UserProtocol, description: str) -> Subraddit:

		Action.events.dispatch(ActionInfo(text=f"creating subraddit '{name}' for owner '{owner.get_name()}'"))
		subraddit = Subraddit.new(name, owner, description)
		Locator.main.database.set_subraddit(subraddit)
		owner.add_owned_subraddit(subraddit.get_key())
		return subraddit

	@staticmethod
	def create_subraddit_post(
		user: protocols.UserProtocol,
		subraddit: protocols.SubradditProtocol,
		title: str, text: str
	) -> Post:

		Action.events.dispatch(ActionInfo(text=f"creating toplevel post in subraddit '{subraddit.get_name()}' for author '{user.get_name()}' titled '{title}'"))
		post = Post.new(author=user, text=text, title=title, parent=None)
		Locator.main.database.set_post(post)
		post.subscribe(user)
		subraddit.add_post(post)
		Action.events.dispatch(ActionInfo(text=f"created toplevel post {post.get_key()}"))
		return post

	@staticmethod
	def create_post(
		user: protocols.UserProtocol,
		parent: protocols.PostProtocol,
		text: str,
	) -> Post:

		Action.events.dispatch(ActionInfo(text=f"creating post for {user.get_name()} with parent {parent.get_key()}"))
		post = Post.new(author=user, text=text, title="replying", parent=parent.get_key())
		Locator.main.database.set_post(post)
		post.subscribe(user)
		parent.add_child(post)
		Action.events.dispatch(ActionInfo(text=f"created post {post.get_key()}"))

		for key in parent.get_subscribers():

			subscriber = Locator.main.database.get_user(key)

			if subscriber is not None:
				Action.notify(
					subscriber,
					f"Activity on {parent.get_title()}",
					post.get_text()[:100],
					f"/post/{post.get_key()}",
				)

		return post

	@staticmethod
	def send_private_message(
		sender: protocols.UserProtocol,
		receiver: protocols.UserProtocol,
		text: str,
	) -> PrivateMessage:

		private_message = PrivateMessage.new(author=sender.get_name(), text=text)
		Locator.main.database.set_private_message(private_message)
		receiver.add_private_message(private_message.get_key())
		return private_message

	@staticmethod
	def notify(target: protocols.UserProtocol, title: str, text: str, link: str) -> Notification:

		Action.events.dispatch(ActionInfo(text=f"notifying '{target.get_name()}' of '{title}' ({link})"))
		notification = Notification.new(target, text, title, link)
		Locator.main.database.set_notification(notification)
		return notification

class IllegalCharsError(Exception):

	def __init__(self, chars: set[str]):

		super().__init__()
		self.chars = chars

def assert_sane(text: str):

	illegal_chars: set[str] = set(char for char in text if char not in ALLOWED_CHARS)

	if len(illegal_chars) > 0:
		raise IllegalCharsError(illegal_chars)

def print_header(console: Console):

	user: User = session.get("user", None)

	if user is not None:

		unread_notifications_count = user.get_unread_notifications_count()
		notif_alert = f"[bold red]({unread_notifications_count})[/bold red]" if unread_notifications_count > 0 else ""

		console.print(Padding(Panel(
			f"[bold cyan][link=/]Raddit[/link][/bold cyan]"
			f" | [bold] > [green]{user.get_name()}[/green]"
			f" | {datetime.now().strftime(r'%a %d %Y %H:%M')}"
			f" | [bold yellow][link=/search_sub]Search for a subraddit[/link][/bold yellow]"
			f" | [bold yellow][link=/account]Account[/link][/bold yellow]"
			f" | [bold yellow][link=/notifications]Notifications{notif_alert}[/link][/bold yellow]"
			f" | [bold yellow][link=/see_private_messages]Private messages[/link][/bold yellow]"
			f" | [bold yellow][link=/log_off]log off[/link][/bold yellow][/bold]"
		), (2, 2)), justify="center")

	else:
		console.print(Padding(Panel(
			"[bold cyan][link=/]Raddit[/link][/bold cyan]"
			" | [bold yellow][link=/register]register[/link][/bold yellow]"
			" | [bold yellow][link=/login]login[/link][/bold yellow]"
			" | [bold yellow][link=/search_sub]Search for a subraddit[/link][/bold yellow]"
		), (2, 2)), justify="center")

def print_post(
	console: Console,
	post_key: protocols.Key,
	post_text_char_limit: int = 100,
	indent_level: int = 0,
	rec: int = 3,
):

	post: Optional[protocols.PostProtocol] = Locator.main.database.get_post(post_key)

	if post is None:

		console.print(Padding(Panel("///", title="[red]cannot load post[/red]"), (0, INDENT_SIZE*indent_level)))
		return

	text: Markdown = Markdown(post.get_text()[:post_text_char_limit])
	read_more_link_text: str = "... read more | " if len(post.get_text()) > post_text_char_limit else ""
	author: Optional[protocols.UserProtocol] = post.get_author()
	author_name = f"[bold]{author.get_name()}[/bold]" if author is not None else "[red][deleted][/red]"
	subscribe_text = f"[italic yellow][link=/subscribe/{post.get_key()}]subscribe[/link][/italic yellow]"
	unsubscribe_text = f"[italic yellow][link=/unsubscribe/{post.get_key()}]unsubscribe[/link][/italic yellow]"
	user: Optional[protocols.UserProtocol] = Action.get_session_user()

	if user is None:
		subscribe_action = ""
		reply_action = ""

	else:
		subscribe_action = f" | {unsubscribe_text if post.is_subscribed(user) else subscribe_text}"
		reply_action = f" | [yellow][link=/create_post/{post.get_key()}]reply[/link][/yellow]"

	fmt_time = post.get_timestamp().strftime(r"%a %d %Y %H:%M")

	console.print(Padding(
		Panel(
			text,
			title=f"{author_name} > {post.get_title()}",
			subtitle=(
				f"[italic yellow][link=/post/{post.get_key()}]{read_more_link_text}[/link][/italic yellow]"
				f"[italic yellow][link=/post/{post.get_key()}]{post.get_children_count()} replies[/link][/italic yellow]"
				f" | {fmt_time} | {post.get_subscribers_count()} subscribers"
				f"{subscribe_action}"
				f"{reply_action}"
			)
		),
		(1, INDENT_SIZE*indent_level),
	))

	if rec <= 0: return

	for child in post.get_children():
		print_post(
			console,
			post_key=child,
			post_text_char_limit=post_text_char_limit,
			indent_level=indent_level + 1,
			rec=rec - 1,
		)

def print_notification(console: Console, notification: protocols.NotificationProtocol):

	style: str = "normal" if notification.get_read() else "on blue"
	console.print(Panel(
		f"[{style}][link=/notification/{notification.get_key()}]{notification.get_text()}[/link][/{style}]",
		title=f"[bold]{notification.get_title()}[/bold]",
	))

HTML_BASE: str = """
	<!DOCTYPE html>
	<head>
		<meta charset='UTF-8'>
		<link rel="stylesheet" href="/static/style.css">
		<style>
		{stylesheet}
		</style>
	</head>
	<body>
		<code>
			<pre style="font-family:Menlo,'DejaVu Sans Mono',consolas,'Courier New',monospace">
			{code}
			</pre>
		</code>
	</body>
"""

def make_console() -> Console:
	
	console = Console(record=True, file=StringIO(), style="white on black", width=100, height=100)
	console.print("")
	return console

def get_html(console: Console) -> str:
	return console.export_html(code_format=HTML_BASE)

@app.route("/")
def home():

	console = make_console()
	print_header(console)

	console.print(Panel.fit(
		"[royal_blue1]"
		"[cyan]Raddit[/cyan] is a sort of [bold]small[/bold], [bold]non moderated[/bold] forum."
		" The idea is simply to let people write what they want. Once something is written, "
		"it can't be removed or edited. Just claim a part of the site as yours (a subraddit) and select"
		" the people you want to fill it with thoughts, games or whatever. Or simply let the settings on"
		" 'free for all' and see how the title of your subraddit inspire a crowd of strangers. "
		"This is only for the toplevel posts of your subraddit though: you can't restrict users from"
		" reacting and replying to those posts."
		"[/royal_blue1]"
		"",
		title="What is [cyan]Raddit[/cyan]?",
	)),
	console.print(Panel.fit(
		"[royal_blue1]"
		"Free speech comes with pros and cons: you can express yourself freely but so can other people."
		" The creators of this site do not necessarily approve anything that's written in posts: actually"
		" they don't even intend to read most of it."
		"\n[green]Debate, mock, share, cry: [cyan]Raddit[/cyan] does or doesn't care, but will move"
		" forward regardless.[/green]"
		"[/royal_blue1]"
		"",
		title="This is [bold]not[/bold] a safe space",
	)),
	console.print(Panel.fit(
		"[royal_blue1]"
		"You can just lurk around if you will. However, most of the fun of [cyan]Raddit[/cyan] resides"
		" in participating, publicly or in private messages. To do that you need an account, which only "
		"requires having an email address. Your email address will remain private, but we still encourage"
		" you to make one specifically for this purpose (it will only be required once at account creation)."
		"[/royal_blue1]",
		title="About account",
	))
	console.print(Panel.fit(
		"[royal_blue1]"
		"You can use the search option to check a few interesting subraddits: [yellow]help[/yellow] or "
		"[yellow]raddit_update[/yellow]"
		"[/royal_blue1]",
		title="Where do I go from here?",
	))

	return get_html(console)

@app.route("/change_password", methods=["POST",])
def change_password():

	console = make_console()
	user  = Action.get_session_user()

	if user is None:
		console.print("[bold red] You are not logged in")
		return get_html(console)

	print_header(console)

	try:
		old_password, new_password = request.form["old_password"], request.form["new_password"]

	except KeyError:
		console.print("[bold red] Something went wrong")
		return get_html(console)

	if protocols.hash(old_password) != user.get_password_hash():
		console.print("[bold red] Wrong password")
		return get_html(console)

	try:
		assert_sane(new_password)

	except IllegalCharsError as e:
		console.print(f"[bold red] Forbidden chars: {e.chars}")
		return get_html(console)

	Action.change_password(user, new_password)
	console.print(f"[bold green] Password successfully changed")
	return get_html(console)

@app.route("/manage_sub/<key>")
def manage_sub(key: str):
	
	console = make_console()
	user = Action.get_session_user()

	if user is None:
		console.print("[bold red] You are not logged in")
		return get_html(console)

	print_header(console)

	try:
		assert_sane(key)

	except IllegalCharsError:
		console.print("[bold red] Something went wrong")
		return get_html(console)

	if not user.own_subraddit(key):
		console.print("[bold red] You don't own this subraddit")
		return get_html(console)

	key = Action.cast_key(key)
	subraddit = Locator.main.database.get_subraddit(key)

	if subraddit is None:
		console.print("[bold red] This subraddit doesn't exist")
		return get_html(console)

	console.rule(f"[bold]Managing {subraddit.get_name()}[/bold]")

	set_descr_form = f"""
		<form action="/handle_sub_set_description" method="POST">
			<textarea row="20" cols="60" name="description">{subraddit.get_description()}</textarea>
			<input type="hidden" name="sub_key" value="{key}">
			<input type="submit" value="Change description">
		</form>
	"""
	console.print("SET DESCR FORM")

	console.print(Padding(Panel(
		"Posting policy let you decide who can make toplevel posts in your subraddit."
		"\nSet this carefully because once someone makes a post, it's not possible to delete it."
		"\nChanging the post policy to 'free for all' doesn't erase the blacklist or whitelist."
		"\nSimilarly, both of those lists are independant."
	), (4, 4)))

	policy_selection_form = f"""
		<form action="/handle_sub_set_post_policy" method="POST" style="color: #ffffff">
			<input type="radio" name="post_policy" id="f4a" value="Free for all">
			<label for="f4a">Free for all</label>
			<input type="radio" name="post_policy" id="w" value="Whitelist">
			<label for="w">Whitelist</label>
			<input type="radio" name="post_policy" id="b" value="Blacklist">
			<label for="b">Blacklist</label>
			<input type="hidden" name="sub_key" value="{key}">
			<input type="submit" value="Change posting policy">
		</form>
	"""
	console.print("POLICY SELECTION FORM")
	subraddit.clean_post_policy()
	list_add_form = ""

	if subraddit.get_post_policy() is SubradditPostPolicy.whitelist:

		whitelist: list[str] = []

		for name in subraddit.get_whitelist():
			whitelist.append(f"{name} [yellow][link=/sub_rem_whitelist/{key}/{name}]remove[/link][/yellow]")

		console.print(Padding(Panel(
			"\n".join(whitelist),
			title="Whitelist",
		), (4, 4)))

		list_add_form = f"""
			<form action="/handle_sub_add_whitelist" method="POST">
				<input type="text" name="name">
				<input type="hidden" name="sub_key" value="{key}">
				<input type="submit" value="Add">
			</form>
		"""
		console.print("LIST ADD FORM")

	elif subraddit.get_post_policy() is SubradditPostPolicy.blacklist:

		blacklist: list[str] = []

		for name in subraddit.get_blacklist():
			blacklist.append(f"{name} [yellow][link=/sub_rem_blacklist/{key}/{name}]remove[/link][/yellow]")

		console.print(Padding(Panel(
			"\n".join(blacklist),
			title="Blacklist",
		), (4, 4)))

		list_add_form = f"""
			<form action="/handle_sub_add_blacklist" method="POST">
				<input type="text" name="name">
				<input type="hidden" name="sub_key" value="{key}">
				<input type="submit" value="Add">
			</form>
		"""
		console.print("LIST ADD FORM")

	elif subraddit.get_post_policy() is SubradditPostPolicy.free_for_all:

		console.print(Padding(Panel(
			"Everyone can make toplevel posts",
		), (4, 4)))

	else:
		console.print("[bold red] Unknown posting policy (please tell an admin)")

	html = get_html(console)
	html = html.replace("POLICY SELECTION FORM", policy_selection_form)
	html = html.replace("LIST ADD FORM", list_add_form)
	html = html.replace("SET DESCR FORM", set_descr_form)
	return html

@app.route("/handle_sub_set_post_policy", methods=["POST",])
def handle_sub_set_post_policy():
	
	console = make_console()
	user = Action.get_session_user()

	if user is None:
		console.print("[bold red] You are not logged in")
		return get_html(console)

	try:
		key, policy = request.form["sub_key"], request.form["post_policy"]

	except KeyError:
		console.print("[bold red] Something went wrong")
		return get_html(console)

	try:
		assert_sane(key)
		assert_sane(policy)

	except IllegalCharsError:
		console.print("[bold red] Something went wrong")
		return get_html(console)

	if not user.own_subraddit(key):
		console.print("[bold red] You don't own this subraddit")
		return get_html(console)

	key = Action.cast_key(key)
	subraddit = Locator.main.database.get_subraddit(key)

	if subraddit is None:
		console.print("[bold red] This subraddit doesn't exist")
		return get_html(console)

	if policy == "Free for all":
		subraddit.set_post_policy(SubradditPostPolicy.free_for_all)

	elif policy == "Whitelist":
		subraddit.set_post_policy(SubradditPostPolicy.whitelist)

	elif policy == "Blacklist":
		subraddit.set_post_policy(SubradditPostPolicy.blacklist)

	else:
		console.print("[bold red] Something went wrong")
		return get_html(console)

	console.print(f"[bold green] Posting policy successfully set to {subraddit.get_post_policy()}")
	console.print(Padding(Panel.fit(
		f"[yellow][link=/manage_sub/{key}]Go back to managing the subraddit[/link][/yellow]"
	), (4, 4)))
	return get_html(console)

@app.route("/handle_sub_add_whitelist", methods=["POST",])
def handle_sub_add_whitelist():
	
	console = make_console()
	user = Action.get_session_user()

	if user is None:
		console.print("[bold red] You are not logged in")
		return get_html(console)

	try:
		key, name = request.form["sub_key"], request.form["name"]

	except KeyError:
		console.print("[bold red] Something went wrong")
		return get_html(console)

	try:
		assert_sane(key)
		assert_sane(name)

	except IllegalCharsError:
		console.print("[bold red] Something went wrong")
		return get_html(console)

	if not user.own_subraddit(key):
		console.print("[bold red] You don't own this subraddit")
		return get_html(console)

	key = Action.cast_key(key)
	subraddit = Locator.main.database.get_subraddit(key)

	if subraddit is None:
		console.print("[bold red] This subraddit doesn't exist")
		return get_html(console)

	target = Locator.main.database.get_user(name)

	if target is None:
		console.print(f"[bold red] User {name} doesn't exist")
		return get_html(console)

	subraddit.add_whitelist(target)
	console.print(f"[bold green] Successfully added {name} to the whitelist")
	console.print(Padding(Panel.fit(
		f"[yellow][link=/manage_sub/{key}]Go back to managing the subraddit[/link][/yellow]"
	), (4, 4)))
	return get_html(console)

@app.route("/handle_sub_add_blacklist", methods=["POST",])
def handle_sub_add_blacklist():
	
	console = make_console()
	user = Action.get_session_user()

	if user is None:
		console.print("[bold red] You are not logged in")
		return get_html(console)

	try:
		key, name = request.form["sub_key"], request.form["name"]

	except KeyError:
		console.print("[bold red] Something went wrong")
		return get_html(console)

	try:
		assert_sane(key)
		assert_sane(name)

	except IllegalCharsError:
		console.print("[bold red] Something went wrong")
		return get_html(console)

	if not user.own_subraddit(key):
		console.print("[bold red] You don't own this subraddit")
		return get_html(console)

	key = Action.cast_key(key)
	subraddit = Locator.main.database.get_subraddit(key)

	if subraddit is None:
		console.print("[bold red] This subraddit doesn't exist")
		return get_html(console)

	target = Locator.main.database.get_user(name)

	if target is None:
		console.print(f"[bold red] User {name} doesn't exist")
		return get_html(console)

	subraddit.add_blacklist(target)
	console.print(f"[bold green] Successfully added {name} to the blacklist")
	console.print(Padding(Panel.fit(
		f"[yellow][link=/manage_sub/{key}]Go back to managing the subraddit[/link][/yellow]"
	), (4, 4)))
	return get_html(console)

@app.route("/sub_rem_blacklist/<sub_key>/<name>")
def sub_rem_blacklist(sub_key: str, name: str):
	
	console = make_console()
	user = Action.get_session_user()

	if user is None:
		console.print("[bold red] You are not logged in")
		return get_html(console)

	key, name = sub_key, name

	try:
		assert_sane(key)
		assert_sane(name)

	except IllegalCharsError:
		console.print("[bold red] Something went wrong")
		return get_html(console)

	if not user.own_subraddit(key):
		console.print("[bold red] You don't own this subraddit")
		return get_html(console)

	key = Action.cast_key(key)
	subraddit = Locator.main.database.get_subraddit(key)

	if subraddit is None:
		console.print("[bold red] This subraddit doesn't exist")
		return get_html(console)

	target = Locator.main.database.get_user(name)

	if target is None:
		console.print(f"[bold red] User {name} doesn't exist")
		return get_html(console)

	if not subraddit.is_blacklisted(user):
		console.print(f"This user is not blacklisted")
		return get_html(console)

	subraddit.rem_blacklist(target)
	console.print(f"[bold green] Successfully removed {name} from the blacklist")
	console.print(Padding(Panel.fit(
		f"[yellow][link=/manage_sub/{key}]Go back to managing the subraddit[/link][/yellow]"
	), (4, 4)))
	return get_html(console)

@app.route("/sub_rem_whitelist/<sub_key>/<name>")
def sub_rem_whitelist(sub_key: str, name: str):
	
	console = make_console()
	user = Action.get_session_user()

	if user is None:
		console.print("[bold red] You are not logged in")
		return get_html(console)

	key, name = sub_key, name

	try:
		assert_sane(key)
		assert_sane(name)

	except IllegalCharsError:
		console.print("[bold red] Something went wrong")
		return get_html(console)

	if not user.own_subraddit(key):
		console.print("[bold red] You don't own this subraddit")
		return get_html(console)

	key = Action.cast_key(key)
	subraddit = Locator.main.database.get_subraddit(key)

	if subraddit is None:
		console.print("[bold red] This subraddit doesn't exist")
		return get_html(console)

	target = Locator.main.database.get_user(name)

	if target is None:
		console.print(f"[bold red] User {name} doesn't exist")
		return get_html(console)

	if not subraddit.is_whitelisted(user):
		console.print(f"This user is not whitelisted")
		return get_html(console)

	subraddit.rem_whitelist(target)
	console.print(f"[bold green] Successfully removed {name} from the whitelist")
	console.print(Padding(Panel.fit(
		f"[yellow][link=/manage_sub/{key}]Go back to managing the subraddit[/link][/yellow]"
	), (4, 4)))
	return get_html(console)

@app.route("/handle_sub_set_description", methods=["POST",])
def handle_sub_set_description():
	
	console = make_console()
	user = Action.get_session_user()

	if user is None:
		console.print("[bold red] You are not logged in")
		return get_html(console)

	try:
		key, description = request.form["sub_key"], request.form["description"]

	except KeyError:
		console.print("[bold red] Something went wrong")
		return get_html(console)

	try:
		assert_sane(key)
		assert_sane(description)

	except IllegalCharsError:
		console.print("[bold red] Something went wrong")
		return get_html(console)

	if len(description) > SUB_DESC_MAX_CHARS:
		console.print(f"[bold red] The description cannot be wider than {SUB_DESC_MAX_CHARS} characters")
		return get_html(console)

	if not user.own_subraddit(key):
		console.print("[bold red] You don't own this subraddit")
		return get_html(console)

	key = Action.cast_key(key)
	subraddit = Locator.main.database.get_subraddit(key)

	if subraddit is None:
		console.print("[bold red] This subraddit doesn't exist")
		return get_html(console)

	subraddit.set_description(description)
	console.print("[bold green] Successfully changed the description!")
	console.print(Padding(Panel.fit(
		f"[yellow][link=/manage_sub/{key}]Go back to managing the subraddit[/link][/yellow]"
	), (4, 4)))
	return get_html(console)

@app.route("/handle_add_pmw", methods=["POST",])
def add_pmw():
	
	console = make_console()
	user = Action.get_session_user()

	if user is None:
		console.print("[bold red] You are not logged in")
		return get_html(console)

	try:
		name = request.form["name"]

	except KeyError:
		console.print("[bold red] Something went wrong")
		return get_html(console)

	try:
		assert_sane(name)

	except IllegalCharsError:
		console.print("[bold red] Something went wrong")
		return get_html(console)

	if name in user.get_private_messages_whitelist():
		console.print(f"{name} is already in your private messages whitelist")
		return get_html(console)

	user.add_pmw(name)
	console.print(f"[bold green] Successfully added {name} to your private messages whitelist")
	console.print(Padding(Panel.fit(
		f"[yellow][link=/account]Go back to account settings[/link][/yellow]"
	), (4, 4)))
	return get_html(console)

@app.route("/rem_pmw/<name>")
def rem_pmw(name: str):
	
	console = make_console()
	user = Action.get_session_user()

	if user is None:
		console.print("[bold red] You are not logged in")
		return get_html(console)

	try:
		assert_sane(name)

	except IllegalCharsError:
		console.print("[bold red] Something went wrong")
		return get_html(console)

	if name not in user.get_private_messages_whitelist():
		console.print(f"{name} is not in your private messages whitelist")
		return get_html(console)

	user.rem_pmw(name)
	console.print(f"[bold green] Successfully removed {name} from your private messages whitelist")
	console.print(Padding(Panel.fit(
		f"[yellow][link=/account]Go back to account settings[/link][/yellow]"
	), (4, 4)))
	return get_html(console)

@app.route("/see_private_messages")
def see_private_messages():

	console = make_console()
	user = Action.get_session_user()

	if user is None:
		console.print("[bold red] You are not logged in")
		return get_html(console)

	print_header(console)
	
	pms: dict[str, int] = {}

	for key in user.get_private_messages():

		message = Locator.main.database.get_private_message(key)
		if message is None: continue
		author = message.get_author()
		if author is None: continue
		is_read = message.get_read()
		pms[author] = pms.get(author, 0) + int(is_read)

	pms = {author: count for author, count in pms.items() if count > 0}

	for name, count in pms.items():
		console.print(Panel.fit(
			f"{name} [red]({count})[/red] [yellow][link=/private_message/{name}]see[/link][/yellow]"
		))

	return get_html(console)

@app.route("/private_messages/<name>")
def see_private_messages_user(name: str):
	
	console = make_console()
	user = Action.get_session_user()

	if user is None:
		console.print("[bold red] You are not logged in")
		return get_html(console)

	print_header(console)

	try:
		assert_sane(name)

	except IllegalCharsError:
		console.print("[bold red] Something went wrong")
		return get_html(console)

	target = Locator.main.database.get_user(name)

	if target is None:
		console.print("[bold red] User doesn't exist")
		return get_html(console)

	target_pms: list[protocols.PrivateMessageProtocol] = []

	for key in user.get_private_messages():

		message = Locator.main.database.get_private_message(key)
		if message is None: continue
		if message.get_author() == target.get_name(): target_pms.append(message)

	user_pms: list[protocols.PrivateMessageProtocol] = []

	for key in target.get_private_messages():

		message = Locator.main.database.get_private_message(key)
		if message is None: continue
		if message.get_author() == user.get_name(): user_pms.append(message)

	while target_pms or user_pms:

		side: Literal['right', 'left', 'center'] = "center"

		if target_pms[0].get_timestamp() > user_pms[0].get_timestamp():
			
			message = user_pms.pop(0)
			side = "right"

		else:

			message = target_pms.pop(0)
			side = "left"

		console.print(Panel(
			message.get_text(),
			title=f"from {message.get_author()}",
			subtitle=str(message.get_timestamp()),
		), justify=side)

	send_pm_form = f"""
		<form action="/handle_send_pm" method="POST">
			<textarea row="20" cols="60" name="text"></textarea>
			<input type="hidden" name="target_name" value="{target.get_name()}">
			<input type="submit" value="Send private message">
		</form>
	"""
	console.print("SEND PM FORM")

	html = get_html(console)
	html = html.replace("SEND PM FORM", send_pm_form)
	return html

@app.route("/handle_send_pm", methods=["POST",])
def handle_send_pm():
	
	console = make_console()
	user = Action.get_session_user()

	if user is None:
		console.print("[bold red] You are not logged in")
		return get_html(console)

	try:
		target_name, text = request.form["target_name"], request.form["text"]

	except KeyError:
		console.print("[bold red] Something went wrong")
		return get_html(console)

	try:
		assert_sane(target_name)

	except IllegalCharsError:
		console.print("[bold red] Something went wrong")
		return get_html(console)

	try:
		assert_sane(text)

	except IllegalCharsError as e:
		console.print(f"[bold red] Illegal chars: {e.chars}")
		return get_html(console)

	target = Locator.main.database.get_user(target_name)

	if target is None:
		console.print("[bold red] User doesn't exist")
		return get_html(console)

	Action.send_private_message(sender=user, receiver=target, text=text)
	return redirect(f"/private_messages/{target.get_name()}")

@app.route("/delete_account")
def delete_account():
	
	console = make_console()
	user = Action.get_session_user()

	if user is None:
		console.print("[bold red] You are not logged in")
		return get_html(console)

	console.print(
		"You are about to delete your account. Your username will still be claimed so no one can impersonate you."
		"\nThe posts you created will still be available, and subraddits you own will still be active."
		"\n[green]Please enter your username to confirm account deletion[/green]"
	)

	delete_form = f"""
		<form action="/handle_delete_account" method="POST">
			<input type="text" name="name">
			<input type="submit" value="Delete my account">
		</form>
	"""
	console.print("DELETE FORM")

	html = get_html(console)
	html = html.replace("DELETE FORM", delete_form)
	return html

@app.route("/handle_delete_account", methods=["POST",])
def handle_delete_account():

	console = make_console()
	user = Action.get_session_user()

	if user is None:
		console.print("[bold red] You are not logged in")
		return get_html(console)

	try:
		name = request.form["name"]

	except KeyError:
		console.print("[bold red] Something went wrong")
		return get_html(console)

	if name != user.get_name():
		console.print("What you typed is not your username")
		return get_html(console)

	Action.delete_account(user)
	session["user"] = None
	console.print("[bold green] Account deleted successfully")
	return get_html(console)

@app.route("/create_sub")
def create_sub():
	
	console = make_console()
	user = Action.get_session_user()

	if user is None:
		console.print("[bold red] You are not logged in")
		return get_html(console)

	print_header(console)

	create_sub_form = f"""
		<form action="/handle_create_sub" method="POST">
			<input type="text" name="name" placeholder="name">
			<textarea rows="20" cols="50" name="description" placeholder="description"></textarea>
			<input type="submit" value="Create a subraddit">
		</form>
	"""
	console.print("CREATE SUB FORM")

	html = get_html(console)
	html = html.replace("CREATE SUB FORM", create_sub_form)
	return html

@app.route("/handle_create_sub", methods=["POST",])
def handle_create_sub():
	
	console = make_console()
	user = Action.get_session_user()

	if user is None:
		console.print("[bold red] You are not logged in")
		return get_html(console)

	try:
		name, description = request.form["name"], request.form["description"]

	except KeyError:
		console.print("[bold red] Something went wrong")
		return get_html(console)

	try:
		assert_sane(name)
		assert_sane(description)

	except IllegalCharsError as e:
		console.print(f"[bold red] Illegal characters: {e.chars}")
		return get_html(console)

	illegal_chars = set(name) - NAME_ALLOWED_CHARS

	if illegal_chars:
		console.print(f"[bold red] Illegal characters in name: {illegal_chars}")
		return get_html(console)

	if Locator.main.database.subraddit_name_taken(name):
		console.print("This subraddit name is already in use")
		return get_html(console)

	Action.create_subraddit(name=name, owner=user, description=description)
	console.print("[bold green] Subraddit successfully created")
	console.print(Padding(Panel.fit(
		f"[yellow][link=/account]Go back to account settings[/link][/yellow]"
	), (4, 4)))
	return get_html(console)

@app.route("/search_sub", methods=["GET", "POST"])
def search_sub():

	console = make_console()
	print_header(console)

	search_sub_form = f"""
		<form action="/search_sub" method="POST">
			<input type="text" name="name">
			<input type="submit" value="Search">
		</form>
	"""
	console.print("SEARCH SUB FORM")
	
	if request.method == "POST":

		try:
			name = request.form["name"]
			assert_sane(name)

		except (KeyError, IllegalCharsError):
			console.print("[bold red] Something went wrong")

		else:

			ans = Locator.main.database.search_subraddit(name)

			if ans is not None:

				name, key = ans
				console.print(f"Found [link=/sub/{key}]{name}[/link]")

			else:
				console.print("Found nothing")

	html = get_html(console)
	html = html.replace("SEARCH SUB FORM", search_sub_form)
	return html

@app.route("/create_toplevel_post/<key>")
def create_toplevel_post(key: str):
	
	console = make_console()
	user = Action.get_session_user()

	if user is None:
		console.print("[bold red] You are not logged in")
		return get_html(console)

	try:
		assert_sane(key)

	except IllegalCharsError:
		console.print("[bold red] Something went wrong")
		return get_html(console)

	subraddit = Locator.main.database.get_subraddit(key)

	if subraddit is None:
		console.print("[bold red] This subraddit doesn't exist")
		return get_html(console)

	if not subraddit.comply_with_post_policy(user):
		console.print("[bold red] The posting policy of this subraddit prevents you from posting")
		return get_html(console)

	create_post_form = f"""
		<form action="/handle_create_toplevel_post" method="POST">
			<input type="text" name="title" placeholder="title">
			<textarea rows="20" cols="50" name="text"></textarea>
			<input type="hidden" name="sub_key" value="{key}">
			<input type="submit" value="Make post">
		</form>
	"""
	console.print("CREATE POST FORM")

	html = get_html(console)
	html = html.replace("CREATE POST FORM", create_post_form)
	return html

@app.route("/handle_create_toplevel_post", methods=["POST",])
def handle_create_toplevel_post():
	
	console = make_console()
	user = Action.get_session_user()

	if user is None:
		console.print("[bold red] You are not logged in")
		return get_html(console)

	try:
		title, text, key = request.form["title"], request.form["text"], request.form["sub_key"]

	except KeyError:
		console.print("[bold red] Something went wrong")
		return get_html(console)

	try:
		assert_sane(key)
		assert_sane(title)
		assert_sane(text)

	except IllegalCharsError as e:
		console.print(f"[bold red] Illegal characters: {e.chars}")
		return get_html(console)

	subraddit = Locator.main.database.get_subraddit(key)

	if subraddit is None:
		console.print("[bold red] This subraddit doesn't exist")
		return get_html(console)

	if not subraddit.comply_with_post_policy(user):
		console.print("[bold red] The posting policy of this subraddit prevents you from posting")
		return get_html(console)

	post = Action.create_subraddit_post(user=user, subraddit=subraddit, title=title, text=text)
	return redirect(f"/post/{post.get_key()}")

@app.route("/create_post/<key>")
def create_post(key: str):
	
	console = make_console()
	user = Action.get_session_user()

	if user is None:
		console.print("[bold red] You are not logged in")
		return get_html(console)

	try:
		assert_sane(key)

	except IllegalCharsError:
		console.print("[bold red] Something went wrong")
		return get_html(console)

	parent = Locator.main.database.get_post(key)

	if parent is None:
		console.print("[bold red] This post doesn't exist")
		return get_html(console)

	print_post(console, key, POST_TEXT_MAX_CHARS, rec=0)

	create_post_form = f"""
		<form action="/handle_create_post" method="POST">
			<textarea rows="20" cols="50" name="text"></textarea>
			<input type="hidden" name="parent_key" value="{key}">
			<input type="submit" value="Reply">
		</form>
	"""
	console.print("CREATE POST FORM")

	html = get_html(console)
	html = html.replace("CREATE POST FORM", create_post_form)
	return html

@app.route("/handle_create_post", methods=["POST",])
def handle_create_post(): # TODO
	
	console = make_console()
	user = Action.get_session_user()

	if user is None:
		console.print("[bold red] You are not logged in")
		return get_html(console)

	try:
		text, key = request.form["text"], request.form["parent_key"]

	except KeyError:
		console.print("[bold red] Something went wrong")
		return get_html(console)

	try:
		assert_sane(key)
		assert_sane(text)

	except IllegalCharsError as e:
		console.print(f"[bold red] Illegal characters: {e.chars}")
		return get_html(console)

	parent = Locator.main.database.get_post(key)

	if parent is None:
		console.print("[bold red] This subraddit doesn't exist")
		return get_html(console)

	post = Action.create_post(user=user, parent=parent, text=text)
	return redirect(f"/post/{post.get_key()}")

@app.route("/account")
def see_account():

	console = make_console()
	user = Action.get_session_user()

	if user is None:
		console.print("[bold red] You are not logged in")
		return get_html(console)

	print_header(console)
	console.print(Padding(Panel(
		f"username: {user.get_name()}"
		f"\nemail address: {user.get_email()}",
		title="General",
	), (4, 4)))

	change_password_form = """
		<form action="/change_password" method="POST">
			<div>Old password: <input type="password" name="old_password"><br></div>
			<div>New password: <input type="password" name="new_password"><br></div>
			<input type="submit" value="Change password">
		</form>
	"""
	console.print("CHANGE PASSWORD FORM")

	owned_subraddits: list[str] = []

	for key in user.get_owned_subraddits():

		subraddit = Locator.main.database.get_subraddit(key)
		if subraddit is None: continue
		owned_subraddits.append(f"{subraddit.get_name()} [italic yellow][link=/manage_sub/{subraddit.get_key()}]manage[/link][/italic yellow]")

	owned_subraddits_text = '\n'.join(owned_subraddits)
	console.print(Padding(Panel(
		f"{owned_subraddits_text}",
		title="Owned subraddits",
	), (4, 4)))

	console.print("[yellow][link=/create_sub]Create a subraddit[/link][/yellow]")

	pmw: list[str] = []

	for name in user.get_private_messages_whitelist():
		pmw.append(f"{name} [yellow][link=/private_messages/{name}]chat[/link][/yellow] | [yellow][link=/rem_pmw/{name}]remove[/link][/yellow]")

	pmw_text = '\n'.join(pmw)
	console.print(Padding(Panel(
		f"{pmw_text}",
		title="Private messages whitelist",
	), (4, 4)))

	add_pmw_form = """
		<form action="/add_pmw" method="POST">
			<div>Username: <input type="text" name="name"><br></div>
			<input type="submit" value="Add user to private messages whitelist">
		</form>
	"""
	console.print("ADD PMW FORM")

	console.print("[bold yellow][link=/delete_account]Delete my account[/link][/bold yellow]")

	html = get_html(console)
	html = html.replace("CHANGE PASSWORD FORM", change_password_form)
	html = html.replace("ADD PMW FORM", add_pmw_form)
	return html

@app.route("/notifications")
def see_notifications():

	console = make_console()
	user = Action.get_session_user()

	if user is None:
		console.print("[bold red] You are not logged in")
		return get_html(console)

	print_header(console)

	for key in list(user.get_notifications())[::-1]:

		notification = Locator.main.database.get_notification(key)
		if notification is None: continue
		print_notification(console, notification)

	return get_html(console)

@app.route("/unsubscribe/<key>")
def unsubscribe(key: str):

	console = make_console()
	user = Action.get_session_user()

	if user is None:
		console.print("[bold red] You are not logged in")
		return get_html(console)

	try:
		assert_sane(key)

	except IllegalCharsError:
		console.print("[bold red] Something went wrong")
		return get_html(console)

	post = Locator.main.database.get_post(key)

	if post is None:
		console.print("[bold red] This post doesn't exists")
		return get_html(console)

	print_header(console)

	if not post.is_subscribed(user):
		console.print("You are not subscribed to this post")
		return get_html(console)

	post.unsubscribe(user)
	console.print("[bold green] Unsubcribed successfully, you won't receive notifications about this post anymore")
	return get_html(console)

@app.route("/subscribe/<key>")
def subscribe(key: str):

	console = make_console()
	user = Action.get_session_user()

	if user is None:
		console.print("[bold red] You are not logged in")
		return get_html(console)

	try:
		assert_sane(key)

	except IllegalCharsError:
		console.print("[bold red] Something went wrong")
		return get_html(console)

	post = Locator.main.database.get_post(key)

	if post is None:
		console.print("[bold red] This post doesn't exists")
		return get_html(console)

	print_header(console)

	if post.is_subscribed(user):
		console.print("You are already subscribed to this post")
		return get_html(console)

	post.subscribe(user)
	console.print("[bold green] Subcribed successfully, you will receive notifications about this post")
	return get_html(console)

@app.route("/notification/<key>")
def see_notification(key: str):

	console = make_console()
	user = Action.get_session_user()

	if user is None:
		console.print("[bold red] You are not logged in")
		return get_html(console)

	print_header(console)

	try:
		assert_sane(key)

	except IllegalCharsError:
		console.print("[bold red] Something went wrong")
		return get_html(console)

	key = Action.cast_key(key)
	notification: Optional[protocols.NotificationProtocol] = Locator.main.database.get_notification(key)

	if notification is None:
		console.print(f"[bold red] This notification doesn't exists")
		return get_html(console)

	if notification.get_target() != user.get_name():
		console.print(f"[bold red] You are not allowed to see this notification!")
		return get_html(console)

	notification.set_read(True)
	return redirect(notification.get_link())

@app.route("/sub/<key>")
def sub(key: str):

	console = make_console()
	user = Action.get_session_user()
	print_header(console)

	try:
		assert_sane(key)

	except IllegalCharsError:
		console.print("[bold red] Something went wrong")
		return get_html(console)

	key = Action.cast_key(key)
	subraddit: Optional[protocols.SubradditProtocol] = Locator.main.database.get_subraddit(key)

	if subraddit is None:
		console.print("[bold red] This subraddit doesn't exists")
		return get_html(console)

	console.rule(f"[bold green]{subraddit.get_name()}[/bold green]")

	owner = subraddit.get_owner()

	console.print(Padding(Panel(
		f"Owner: {owner.get_name() if owner is not None else '[red]deleted[/red]'}"
		f"\nPosting policy: {subraddit.get_post_policy().value}",
		title="General information",
	), (2, 4)), justify="center")
	console.print(Padding(Panel(
		Markdown(subraddit.get_description()),
		title="Description",
	), (2, 4)), justify="center")

	if user is not None:
		console.print(Padding(Panel(
			f"[bold yellow][link=/create_toplevel_post/{subraddit.get_key()}]Make a post here[/link][/bold yellow]" if subraddit.comply_with_post_policy(user) else "[red] You cannot post in this subraddit due to its posting policy [/red]"
		), (4, 4)), justify="center")

	for post in subraddit.get_posts():
		print_post(console, post, rec=0)

	return get_html(console)

@app.route("/post/<key>")
def post(key: str):

	console = make_console()
	print_header(console)

	try:
		assert_sane(key)

	except IllegalCharsError:
		console.print("[bold red] Something went wrong")
		return get_html(console)

	key = Action.cast_key(key)
	post = Locator.main.database.get_post(key)

	if post is None:
		console.print("[bold red] This post doesn't exist")
		return get_html(console)

	parent_key = post.get_parent_key()

	if parent_key is not None:

		parent = Locator.main.database.get_post(parent_key)

		if parent is not None:
			print_post(console, parent_key, POST_TEXT_MAX_CHARS, rec=0)		

	print_post(console, key, POST_TEXT_MAX_CHARS, rec=0)

	if post is None:
		return get_html(console)

	console.rule("[bold]Replies to this post[/bold]")

	for reply in post.get_children():
		print_post(console, reply, POST_REPLY_MAX_CHARS)

	return get_html(console)

@app.route("/log_off")
def log_off():

	session["user"] = None
	return redirect("/")

@app.route("/login")
def login():

	console = make_console()
	console.print("LOGIN_FORM")
	login_form = """
		<form action="/handle_login" method="POST">
			<div>Name: <input type="text" name="name"><br></div>
			<div>Password: <input type="password" name="password"><br></div>
			<input type="submit" value="Submit">
		</form>
	"""
	html = get_html(console)
	html = html.replace("LOGIN_FORM", login_form)
	return html

@app.route("/handle_login", methods=["POST"])
def handle_login():

	console = make_console()

	try:
		name, password = request.form["name"], request.form["password"]

	except KeyError:
		console.print("[bold red] Something went wrong")
		return get_html(console)

	try:
		assert_sane(name)
		assert_sane(password)

	except IllegalCharsError as e:
		console.print(f"[bold red] Those characters aren't allowed: {e.chars}")
		return get_html(console)

	user: Optional[User] = Locator.main.database.get_user(name)

	if user is None:
		console.print(f"[bold red] No such user '{name}'")
		return get_html(console)

	if user.is_deleted():
		console.print(f"[bold red] This account was deleted")
		return get_html(console)

	if protocols.hash(password) != user.get_password_hash():
		console.print("[bold red] Wrong password")
		return get_html(console)

	if not user.is_email_verified():
		console.print(f"[bold red] The email address of this account is not verified. Check your spams or wait for 15 minutes to make another registration attempt.")
		return get_html(console)

	session["user"] = user
	return redirect("/")

@app.route("/register")
def register():
	
	console = make_console()
	console.rule("Account creation")
	console.print(Padding(
		"Only [yellow]protonmail[/yellow] or [yellow]gmail[/yellow] addresses are accepted!"
		"\nYou won't be able to change your email address or your name, chose carefully."
		"\nYour email address won't ever be displayed to other users.",
		(4, 4)
	))
	console.print("REGISTER_FORM")
	register_form = """
		<form action="/handle_registration" method="POST">
			<div>Name: <input type="text" name="name"><br></div>
			<div>Password: <input type="password" name="password"><br></div>
			<div>Email address: <input type="mail" name="email"><br></div>
			<input type="submit" value="Claim username">
		</form>
	"""
	html = get_html(console)
	html = html.replace("REGISTER_FORM", register_form)
	return html

@app.route("/handle_registration", methods=["POST"])
def handle_registration():

	console = make_console()

	try:
		name, password, email = request.form["name"], request.form["password"], request.form["email"]

	except KeyError:
		console.print("[bold red] Something went wrong")
		return get_html(console)

	try:
		assert_sane(name)
		assert_sane(password)
		assert_sane(email)

	except IllegalCharsError as e:
		console.print(f"[bold red] Those characters aren't allowed: {e.chars}")
		return get_html(console)

	illegal_chars = set(name) - NAME_ALLOWED_CHARS

	if illegal_chars:
		console.print(f"Those characters aren't allowed in username: {illegal_chars}")
		return get_html(console)

	if name == "none":
		console.print("You cannot name yourself 'none' for technical reasons (bad coding etc)")
		return get_html(console)

	if len(name) > NAME_MAX_CHARS:
		console.print(f"[bold red] Your name cannot be wider than {NAME_MAX_CHARS} characters")
		return get_html(console)

	if len(name) == 0:
		console.print(f"You need to chose a username")
		return get_html(console)

	if len(password) == 0:
		console.print(f"You need to chose a password")
		return get_html(console)

	if not EMAIL_REGEX.match(email):
		console.print(f"[bold red] Email not valid")
		return get_html(console)

	if Locator.main.database.get_user(name):
		console.print(f"[bold red] This user name is already claimed")
		return get_html(console)

	if Locator.main.database.is_email_used(email):
		console.print("[bold red] This email is already used")
		return get_html(console)

	user = Action.create_user(name, email, password)
	email_verification = Action.create_email_verification(user)
	text: str = (
		f"\n Please visit this address to verify your email: "
		f"\n\t http://{Locator.main.domain}/verify_email/{email_verification.get_key()}"
		f"\n Please make sure to manually copy it until the end!"
		f"\n If you don't verify your email address under 15 minutes, the registration request will be deleted "
		"and you will have to fill the registration form again."
	)

	try:
		Action.send_mail(email, text)

	except TargetNotFound:

		user.delete()
		email_verification.delete()
		console.print(f"[bold red] Couldn't send an email at this address: {email}")
		return get_html(console)

	except UnknownError:

		user.delete()
		email_verification.delete()
		console.print("[bold red] Your registration couldn't be completed for unknown reasons. We are working on it, sorry for the inconvenience.")
		return get_html(console)

	console.print(f"[bold green] Success! Verification email sent at '{email}', you have 15 minutes to verify")
	console.print(f"If you don't verifiy under 15 minutes, the registration request will be deleted and you will have to fill the registration form again.")
	console.print(f"Do not forget to check your spams.")
	console.print(Panel(f"[bold][link=/]Home[/link][/bold]", expand=False))
	return get_html(console)

@app.route("/verify_email/<key>")
def verify_email(key: str):

	console = make_console()

	try:
		assert_sane(key)

	except IllegalCharsError:
		console.print("[bold red] something went wrong")
		return get_html(console)

	key = Action.cast_key(key)
	email_verification: Optional[protocols.EmailVerificationProtocol] = Locator.main.database.get_email_verification(key)

	if email_verification is None:
		console.print("[bold red] this verification code doesn't exists")
		return get_html(console)

	Action.validate_email_address(email_verification)
	console.print("[bold green] Email verified! You can login")
	console.print(Panel(f"[bold][link=/]Home[/link][/bold]", expand=False))
	return get_html(console)

@app.before_request
def update():

	now = datetime.now()

	if Locator.main.timers["medium_update"].check(now):

		Locator.main.database.clean_email_verifications()

def get_app() -> Flask:

	db_dir = Path("databases")
	if not db_dir.exists(): db_dir.mkdir()
	database_file = db_dir/"main.db"
	log_dir = Path("logs")
	tor_dir = Path("torfiles")
	hostname_file = tor_dir/"hostname"

	locator = Locator(database=Database(database_file), log_dir=log_dir)

	if hostname_file.exists():
		
		with open(hostname_file) as file:
			addr = file.read()

		print(f"Onion service available at {addr}")
		locator.domain = addr.strip()

	else:

		print("Couldn't get onion service adddress")
		locator.domain = "localhost"

	if not log_dir.exists(): log_dir.mkdir()
	
	locator.start()

	Action.events.add(Locator.main)

	Locator.main.timers["update"] = Timer(timedelta(seconds=3))
	Locator.main.timers["medium_update"] = Timer(timedelta(minutes=3))
	Locator.main.timers["slow_update"] = Timer(timedelta(minutes=5))
	Locator.main.timers["log_update"] = Timer(timedelta(hours=2))

	return app

app = get_app()

def main():

	with Locator.main:
		app.run(debug=True, host="127.0.0.1", port=80)

if __name__ == "__main__":
	main()
