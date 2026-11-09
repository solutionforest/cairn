#!/usr/bin/env python3
"""Cairn admin UI backend: serves index.html and signs admin API calls. Python 3.8+, stdlib only.

    CAIRN_ACCESS_KEY=... CAIRN_SECRET_KEY=... python3 server.py
"""
import datetime
import hashlib
import hmac
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ENDPOINT = os.environ.get("CAIRN_ENDPOINT", "http://127.0.0.1:9000").rstrip("/")
ACCESS_KEY = os.environ.get("CAIRN_ACCESS_KEY") or os.environ.get("CAIRN_ACCESS_KEY_ID", "")
SECRET_KEY = os.environ.get("CAIRN_SECRET_KEY") or os.environ.get("CAIRN_SECRET_ACCESS_KEY", "")
REGION = os.environ.get("CAIRN_REGION", "us-east-1")
PORT = int(os.environ.get("CAIRN_UI_PORT", "9080"))
HOST = f"127.0.0.1:{PORT}"
BIND = os.environ.get("CAIRN_UI_BIND", "127.0.0.1")
PAGE = (Path(__file__).resolve().parent / "index.html").read_bytes()

READ = re.compile(r"^(info|whoami|buckets|users|access-keys|trash)$")
WRITE = re.compile(r"^(trash/restore|users/[^/]+/(enable|disable)|access-keys/[^/]+/(activate|deactivate))$")
TRASH_QUERY = {"limit", "bucket", "prefix", "cursor"}


def quote(s):
    return urllib.parse.quote(s, safe="-_.~")


def sign(method, path, query, body):
    """Return SigV4 headers for a request to ENDPOINT."""
    url = urllib.parse.urlsplit(ENDPOINT)
    now = datetime.datetime.now(datetime.timezone.utc)
    amz_date, date = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
    body_sha = hashlib.sha256(body).hexdigest()
    headers = {"host": url.netloc, "x-amz-content-sha256": body_sha, "x-amz-date": amz_date}
    if body:
        headers["content-type"] = "application/json"
    names = sorted(headers)
    canonical = "\n".join([
        method, path,
        "&".join(f"{quote(k)}={quote(v)}" for k, v in sorted(query)),
        "".join(f"{k}:{headers[k]}\n" for k in names),
        ";".join(names), body_sha,
    ])
    scope = f"{date}/{REGION}/s3/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    key = ("AWS4" + SECRET_KEY).encode()
    for part in (date, REGION, "s3", "aws4_request"):
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    headers["authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={ACCESS_KEY}/{scope}, "
        f"SignedHeaders={';'.join(names)}, Signature={signature}"
    )
    return headers


def call(method, path, query, body):
    """Call /_cairn/v1/<path>; returns (status, json bytes)."""
    base = urllib.parse.urlsplit(ENDPOINT).path.rstrip("/")
    full = base + "/_cairn/v1/" + "/".join(quote(urllib.parse.unquote(p)) for p in path.split("/"))
    qs = "&".join(f"{quote(k)}={quote(v)}" for k, v in sorted(query))
    req = urllib.request.Request(
        urllib.parse.urlsplit(ENDPOINT)._replace(path=full, query=qs).geturl(),
        data=body if method == "POST" else None, method=method,
        headers=sign(method, full, query, body),
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


class Handler(BaseHTTPRequestHandler):
    server_version = "cairn-admin-ui"

    def send(self, status, body, ctype="application/json; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; "
                         "style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def error(self, status, message):
        self.send(status, json.dumps({"error": message}).encode())

    def handle_any(self, method):
        if self.headers.get("Host") != HOST:
            return self.error(403, "Forbidden host")
        url = urllib.parse.urlsplit(self.path)
        if method == "GET" and url.path in ("/", "/index.html"):
            return self.send(200, PAGE, "text/html; charset=utf-8")
        if not url.path.startswith("/api/") or self.headers.get("X-Cairn-UI") != "1":
            return self.error(404, "Not found")
        origin = self.headers.get("Origin")
        if origin and origin != f"http://{HOST}":
            return self.error(403, "Forbidden origin")
        path = url.path[len("/api/"):]
        if not (READ if method == "GET" else WRITE).match(path):
            return self.error(404, "Not found")
        query = [(k, v) for k, v in urllib.parse.parse_qsl(url.query) if path == "trash" and k in TRASH_QUERY]
        body = b""
        if method == "POST":
            length = int(self.headers.get("Content-Length") or 0)
            if length > 64 * 1024:
                return self.error(413, "Body too large")
            body = self.rfile.read(length)
            if path != "trash/restore":
                body = b""
        try:
            status, data = call(method, path, query, body)
        except OSError:
            return self.error(502, f"Cannot reach Cairn at {ENDPOINT}")
        self.send(status, data or b"{}")

    def do_GET(self):
        self.handle_any("GET")

    def do_POST(self):
        self.handle_any("POST")

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.command, self.path.split("?")[0]))


if __name__ == "__main__":
    if not ACCESS_KEY or not SECRET_KEY:
        sys.exit("Set CAIRN_ACCESS_KEY and CAIRN_SECRET_KEY.")
    print(f"Cairn admin: http://{HOST}  (Cairn at {ENDPOINT})")
    ThreadingHTTPServer((BIND, PORT), Handler).serve_forever()
