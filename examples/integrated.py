"""The other side of examples/integrated.sh, with Python's standard library only: an OAuth client of
the authorization code grant with PKCE (urllib, hashlib) that fills the login form as a browser
would, and the mail clients smtplib, imaplib and poplib with SASL OAUTHBEARER (RFC 7628).

    python3 integrated.py code ISSUER USER PASSWORD SCOPE      # prints the token response
    python3 integrated.py smtp PORT TOKEN FROM TO SUBJECT
    python3 integrated.py imap PORT TOKEN
    python3 integrated.py pop3 PORT TOKEN
    python3 integrated.py verify ISSUER USER_CODE USER PASSWORD
"""

import base64
import hashlib
import html.parser
import http.client
import imaplib
import json
import poplib
import secrets
import smtplib
import sys
import urllib.parse


class Form(html.parser.HTMLParser):
    """The fields of the forms of a page."""

    def __init__(self) -> None:
        super().__init__()
        self.fields: dict[str, str] = {}

    def handle_starttag(self, tag: str, attributes: list[tuple[str, str | None]]) -> None:
        values = dict(attributes)
        if tag == "input" and values.get("name"):
            self.fields[values["name"]] = values.get("value") or ""


def request(method: str, url: str, body: dict[str, str] | None = None, headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], bytes]:
    """A request that does not follow redirects, as the client must see them."""
    split = urllib.parse.urlsplit(url)
    connection = http.client.HTTPConnection(split.hostname, split.port)
    data = urllib.parse.urlencode(body).encode() if body is not None else None
    all_headers = {"content-type": "application/x-www-form-urlencoded"} if data is not None else {}
    all_headers.update(headers or {})
    connection.request(method, split.path + (f"?{split.query}" if split.query else ""), body=data, headers=all_headers)
    response = connection.getresponse()
    return response.status, {name.lower(): value for name, value in response.getheaders()}, response.read()


def code(issuer: str, user: str, password: str, scope: str) -> None:
    metadata = json.loads(request("GET", f"{issuer}/.well-known/oauth-authorization-server")[2])
    assert metadata["issuer"] == issuer, metadata
    verifier = secrets.token_urlsafe(32)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state = secrets.token_urlsafe(16)
    redirect = "http://127.0.0.1:49152/cb"  # RFC 8252 §7.3: any port of the registered loopback URI
    query = urllib.parse.urlencode({"response_type": "code", "client_id": "cli", "redirect_uri": redirect, "scope": scope, "state": state, "code_challenge": challenge, "code_challenge_method": "S256"})
    status, _, page = request("GET", f"{metadata['authorization_endpoint']}?{query}")
    assert status == 200, page
    form = Form()
    form.feed(page.decode())
    status, headers, page = request("POST", metadata["authorization_endpoint"], {"consent": form.fields["consent"], "user": user, "password": password, "decision": "allow"})
    assert status == 302, (status, page)
    returned = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(headers["location"]).query))
    # RFC 6749 §10.12 and RFC 9207 §2.4: the state and the issuer of the response.
    assert returned["state"] == state and returned["iss"] == issuer, returned
    status, _, body = request("POST", metadata["token_endpoint"], {"grant_type": "authorization_code", "code": returned["code"], "redirect_uri": redirect, "client_id": "cli", "code_verifier": verifier})
    assert status == 200, body
    print(body.decode())


def verify(issuer: str, user_code: str, user: str, password: str) -> None:
    status, _, page = request("POST", f"{issuer}/device/verify", {"user_code": user_code, "user": user, "password": password})
    print(status, "connected" if b"connected" in page else page.decode())


def oauthbearer(user: str, token: str) -> str:
    """The client response of OAUTHBEARER (RFC 7628 §3.1); without a user, no authzid (RFC 5801 §4)."""
    header = f"n,a={user}," if user else "n,,"
    return f"{header}\x01auth=Bearer {token}\x01\x01"


def smtp(port: str, token: str, sender: str, recipient: str, subject: str) -> None:
    with smtplib.SMTP("127.0.0.1", int(port)) as client:
        client.ehlo("client.test")
        client.auth("OAUTHBEARER", lambda challenge=None: oauthbearer(sender, token) if challenge is None else "\x01", initial_response_ok=True)
        message = f"From: {sender}@umilib.test\r\nTo: {recipient}@umilib.test\r\nSubject: {subject}\r\n\r\nSent with OAUTHBEARER.\r\n"
        client.sendmail(f"{sender}@umilib.test", [f"{recipient}@umilib.test"], message)
    print("sent:", subject)


def imap(port: str, token: str) -> None:
    client = imaplib.IMAP4("127.0.0.1", int(port))
    client.authenticate("OAUTHBEARER", lambda challenge: oauthbearer("", token).encode() if not challenge else b"\x01")
    status, data = client.select("INBOX", readonly=True)
    print("select:", status, data[0].decode())
    count = int(data[0])
    if count:
        status, data = client.fetch(f"1:{count}", "(RFC822)")
        for part in data:
            if isinstance(part, tuple):
                subject = next((line for line in part[1].decode().splitlines() if line.startswith("Subject: ")), "")
                print("fetch:", subject)
    client.logout()


def pop3(port: str, token: str) -> None:
    client = poplib.POP3("127.0.0.1", int(port))
    # poplib has no SASL: the command of RFC 5034 §4. A token is longer than the 255 octets of a
    # command line (RFC 2449 §4), so the response follows the server's empty challenge.
    response = base64.b64encode(oauthbearer("", token).encode()).decode()
    assert client._shortcmd("AUTH OAUTHBEARER").startswith(b"+")
    print("auth:", client._shortcmd(response).decode())
    count, size = client.stat()
    print("stat:", count, size)
    for number in range(1, count + 1):
        lines = client.retr(number)[1]
        print("retr:", next((line.decode() for line in lines if line.startswith(b"Subject: ")), ""))
    client.quit()


if __name__ == "__main__":
    command, *arguments = sys.argv[1:]
    {"code": code, "verify": verify, "smtp": smtp, "imap": imap, "pop3": pop3}[command](*arguments)
