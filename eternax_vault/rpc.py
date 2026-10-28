"""Minimal Bitcoin Core JSON-RPC client.

Credentials come from the URL (http://user:pass@127.0.0.1:18443) or from a cookie file
(the .cookie Bitcoin Core writes in its data directory).
"""
from __future__ import annotations

import base64
import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


class RPC:
    def __init__(self, url: str, cookie: str | None = None, wallet: str | None = None):
        parts = urllib.parse.urlsplit(url)
        if cookie:
            auth = Path(cookie).expanduser().read_text().strip()
        else:
            auth = f"{urllib.parse.unquote(parts.username or '')}:{urllib.parse.unquote(parts.password or '')}"
        netloc = parts.hostname + (f":{parts.port}" if parts.port else "")
        path = f"/wallet/{urllib.parse.quote(wallet)}" if wallet else parts.path
        self.url = urllib.parse.urlunsplit((parts.scheme, netloc, path, "", ""))
        self.auth = base64.b64encode(auth.encode()).decode()
        self.base_url, self.cookie = url, cookie

    def wallet(self, name: str) -> "RPC":
        return RPC(self.base_url, self.cookie, wallet=name)

    def __call__(self, method: str, *params):
        body = json.dumps({"jsonrpc": "1.0", "id": method, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(self.url, data=body, headers={"Authorization": "Basic " + self.auth,
                                                                   "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                res = json.loads(r.read())
        except urllib.error.HTTPError as e:          # Core reports RPC errors as HTTP 500 with a JSON body
            res = json.loads(e.read() or b"{}")
            if not res:
                raise
        if res.get("error"):
            raise RuntimeError(f"{method}: {res['error'].get('message', res['error'])}")
        return res["result"]
