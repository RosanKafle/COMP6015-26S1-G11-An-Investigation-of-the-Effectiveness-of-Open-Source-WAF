"""Small authenticated ZAP API adapter; it never uses the target proxy for API calls."""
import json
from urllib.parse import urlencode
from lab_http import request

class ZapClient:
    def __init__(self, config):
        self.config = config
    def call(self, component, kind, action, **params):
        response = request(self.config.zap_url, f"/JSON/{component}/{kind}/{action}/",
                           method="POST", body=urlencode(params).encode("ascii"),
                           headers={"X-ZAP-API-Key": self.config.zap_api_key, "Content-Type": "application/x-www-form-urlencoded"},
                           timeout=self.config.timeout, max_bytes=self.config.max_response_bytes)
        if response.status != 200:
            raise ValueError(f"ZAP API {component}/{action} returned HTTP {response.status}.")
        data = json.loads(response.body)
        if response.truncated or not isinstance(data, dict) or "code" in data:
            raise ValueError(f"ZAP API {component}/{action} failed or exceeded the response limit.")
        return data
    def version(self):
        return self.call("core", "view", "version")["version"]
