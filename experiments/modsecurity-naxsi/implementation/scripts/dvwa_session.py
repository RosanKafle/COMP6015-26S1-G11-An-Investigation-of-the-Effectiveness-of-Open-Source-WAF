"""Restore the legacy requests.Session and browser headers, with real DVWA login."""
from html.parser import HTMLParser
from http.cookies import SimpleCookie
import time
from urllib.parse import urlsplit
from uuid import uuid4
import requests
from lab_http import Response, validate_endpoint, validate_url

BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "identity",
    "Connection": "keep-alive", "Upgrade-Insecure-Requests": "1",
}

class Tokens(HTMLParser):
    def __init__(self):
        super().__init__()
        self.values = {}
    def handle_starttag(self, tag, attrs):
        fields = dict(attrs)
        if tag == "input" and fields.get("type", "").lower() == "hidden" and fields.get("name"):
            self.values[fields["name"]] = fields.get("value", "")

class DVWASession:
    """One session per WAF run; never follow redirects or retry measured requests."""
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers.update(BROWSER_HEADERS)
        self.session.headers["Referer"] = config.target_url + "/"
        self.renewals = 0
        if config.transport == "zap":
            self.session.proxies.update({"http": config.zap_url, "https": config.zap_url})
        host = urlsplit(config.target_url).hostname
        self.session.cookies.set("security", "low", domain=host, path="/")
        if config.cookie:
            jar = SimpleCookie()
            jar.load(config.cookie)
            for key, item in jar.items():
                self.session.cookies.set(key, item.value, domain=host, path="/")

    def request(self, endpoint, method="GET", encoded="", headers=None):
        validate_url(self.config.target_url)
        validate_endpoint(endpoint)
        if method not in {"GET", "POST"}:
            raise ValueError("Unsupported request method.")
        url = self.config.target_url + endpoint
        kwargs = {"headers": headers or {}, "timeout": self.config.timeout,
                  "allow_redirects": False, "stream": True}
        if method == "GET" and encoded:
            url += "?" + encoded
        elif method == "POST":
            kwargs["data"] = encoded.encode("ascii")
            kwargs["headers"] = {"Content-Type": "application/x-www-form-urlencoded", **kwargs["headers"]}
        started = time.monotonic()
        with self.session.request(method, url, **kwargs) as result:
            data = bytearray()
            for chunk in result.iter_content(8192):
                data.extend(chunk)
                if len(data) > self.config.max_response_bytes:
                    break
                if time.monotonic() - started > self.config.timeout:
                    raise TimeoutError("Response time budget exceeded.")
            return Response(result.status_code, bytes(data[:self.config.max_response_bytes]),
                            {k.lower(): v for k,v in result.headers.items()},
                            len(data) > self.config.max_response_bytes)

    def check(self):
        response = self.request("/index.php", headers={"X-Lab-Request-ID": "auth-" + uuid4().hex})
        # The configured DVWA home page must actually be authenticated.
        body = response.body.decode("utf-8", errors="replace").lower()
        return response.status == 200 and "logout.php" in body and 'name="password"' not in body

    def login(self):
        from urllib.parse import urlencode
        c = self.config
        if c.auth_mode == "none":
            raise ValueError("DVWA experiment requires password or cookie authentication.")
        if c.auth_mode == "cookie":
            if not c.cookie or not self.check():
                raise ValueError("The supplied DVWA session is not authenticated.")
            return
        if not c.username or not c.password:
            raise ValueError("Set DVWA_USERNAME and DVWA_PASSWORD in the private .env.")
        response = self.request("/login.php", headers={"X-Lab-Request-ID": "auth-" + uuid4().hex})
        if response.status != 200:
            raise ValueError("DVWA login page unavailable; inspect WAF/backend evidence.")
        parser = Tokens()
        parser.feed(response.body.decode("utf-8", errors="replace"))
        form = {**parser.values, "username": c.username, "password": c.password, "Login": "Login"}
        response = self.request("/login.php", "POST", urlencode(form),
                                {"X-Lab-Request-ID": "auth-" + uuid4().hex})
        if response.status not in (200, 302, 303) or not self.check():
            raise ValueError("DVWA authentication failed; no experiment requests sent.")
        self.renewals += 1

    def ensure_authenticated(self):
        if not self.check():
            self.login()

    def close(self):
        self.session.close()
