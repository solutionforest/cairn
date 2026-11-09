"""Tests for admin-ui/server.py and admin-ui/server.php against a fake Tidemark that verifies SigV4.

Run: python3 scripts/tests/admin_ui_test.py   (PHP is tested only if `php` is on PATH)
"""

import datetime
import hashlib
import hmac
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AK = "TDMKUITEST0000000000"
SK = "ui-test-secret-0000000000000000000000000"
REGION = "us-east-1"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def verify_sigv4(method, raw_path, headers, body):
    """Independent SigV4 check; returns None if valid, else the reason."""
    auth = headers.get("authorization", "")
    if not auth.startswith("AWS4-HMAC-SHA256 "):
        return "no sigv4 authorization"
    fields = dict(p.strip().split("=", 1) for p in auth[len("AWS4-HMAC-SHA256 "):].split(","))
    cred = fields["Credential"].split("/")
    if cred[0] != AK:
        return f"wrong access key {cred[0]}"
    signed = fields["SignedHeaders"].split(";")
    if hashlib.sha256(body).hexdigest() != headers.get("x-amz-content-sha256"):
        return "body hash mismatch"
    amz_date = headers["x-amz-date"]
    then = datetime.datetime.strptime(amz_date, "%Y%m%dT%H%M%SZ").replace(tzinfo=datetime.timezone.utc)
    if abs((datetime.datetime.now(datetime.timezone.utc) - then).total_seconds()) > 300:
        return "stale x-amz-date"
    url = urllib.parse.urlsplit(raw_path)
    q = lambda s: urllib.parse.quote(s, safe="-_.~")
    query = "&".join(f"{q(k)}={q(v)}" for k, v in sorted(urllib.parse.parse_qsl(url.query, keep_blank_values=True)))
    canonical = "\n".join([
        method, url.path, query,
        "".join(f"{h}:{headers[h].strip()}\n" for h in signed),
        ";".join(signed), headers["x-amz-content-sha256"],
    ])
    scope = "/".join(cred[1:])
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    key = ("AWS4" + SK).encode()
    for part in cred[1:]:
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    if hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest() != fields["Signature"]:
        return "bad signature"
    return None


class FakeTidemark(BaseHTTPRequestHandler):
    seen = []

    def log_message(self, *a):
        pass

    def handle_any(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        headers = {k.lower(): v for k, v in self.headers.items()}
        err = verify_sigv4(self.command, self.path, headers, body)
        FakeTidemark.seen.append({"method": self.command, "path": self.path, "body": body, "err": err})
        out = json.dumps({"error": err} if err else {"ok": True, "path": self.path}).encode()
        self.send_response(403 if err else 200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    do_GET = do_POST = handle_any


class Backend:
    """Common checks; subclasses start one backend."""

    def setUp(self):
        FakeTidemark.seen.clear()
        self.host = f"127.0.0.1:{self.port}"

    def req(self, path, method="GET", body=None, host=None, origin=None, ui=True):
        r = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=body, method=method)
        r.add_header("Host", host or self.host)
        if ui:
            r.add_header("X-Tidemark-UI", "1")
        if origin:
            r.add_header("Origin", origin)
        if body is not None:
            r.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(r, timeout=10) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def test_page_served_without_secrets(self):
        status, body = self.req("/", ui=False)
        self.assertEqual(status, 200)
        self.assertNotIn(SK.encode(), body)
        self.assertNotIn(AK.encode(), body)

    def test_wrong_host_rejected(self):
        self.assertEqual(self.req("/api/info", host="evil.example")[0], 403)
        self.assertEqual(FakeTidemark.seen, [])

    def test_wrong_origin_rejected(self):
        self.assertEqual(self.req("/api/info", origin="http://evil.example")[0], 403)
        self.assertEqual(FakeTidemark.seen, [])

    def test_api_needs_ui_header(self):
        self.assertEqual(self.req("/api/info", ui=False)[0], 404)

    def test_read_is_signed_correctly(self):
        status, body = self.req("/api/info", origin=f"http://{self.host}")
        self.assertEqual(status, 200, body)
        self.assertEqual(FakeTidemark.seen[-1]["err"], None)
        self.assertEqual(FakeTidemark.seen[-1]["path"], "/_tidemark/v1/info")

    def test_unlisted_paths_and_methods_refused(self):
        for path, method in [("/api/users/a/delete", "POST"), ("/api/trash/restore", "GET"),
                             ("/api/info", "POST"), ("/api/../info", "GET")]:
            self.assertEqual(self.req(path, method, body=b"{}" if method == "POST" else None)[0], 404, path)
        self.assertEqual(FakeTidemark.seen, [])

    def test_trash_query_is_filtered_and_signed(self):
        status, _ = self.req("/api/trash?limit=5&prefix=a%20b&evil=1")
        self.assertEqual(status, 200)
        seen = FakeTidemark.seen[-1]
        self.assertEqual(seen["err"], None)
        self.assertEqual(urllib.parse.parse_qs(urllib.parse.urlsplit(seen["path"]).query),
                         {"limit": ["5"], "prefix": ["a b"]})

    def test_restore_forwards_signed_body(self):
        body = b'{"bucket":"photos","key":"cat.jpg"}'
        self.assertEqual(self.req("/api/trash/restore", "POST", body)[0], 200)
        seen = FakeTidemark.seen[-1]
        self.assertEqual((seen["err"], seen["body"]), (None, body))

    def test_other_writes_drop_the_body(self):
        self.assertEqual(self.req("/api/users/alice/disable", "POST", b'{"x":1}')[0], 200)
        seen = FakeTidemark.seen[-1]
        self.assertEqual((seen["err"], seen["path"], seen["body"]), (None, "/_tidemark/v1/users/alice/disable", b""))


def start(cmd, port, env):
    p = subprocess.Popen(cmd, cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.1).close()
            return p
        except OSError:
            time.sleep(0.05)
    p.kill()
    raise RuntimeError(f"{cmd[0]} backend did not start")


upstream = ThreadingHTTPServer(("127.0.0.1", 0), FakeTidemark)
threading.Thread(target=upstream.serve_forever, daemon=True).start()
ENV = dict(os.environ, TIDEMARK_ENDPOINT=f"http://127.0.0.1:{upstream.server_port}",
           TIDEMARK_ACCESS_KEY=AK, TIDEMARK_SECRET_KEY=SK)


class PythonBackend(Backend, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = free_port()
        cls.proc = start([sys.executable, "admin-ui/server.py"], cls.port, dict(ENV, TIDEMARK_UI_PORT=str(cls.port)))

    @classmethod
    def tearDownClass(cls):
        cls.proc.kill()
        cls.proc.wait()

    def test_oversized_body_rejected(self):
        try:
            status = self.req("/api/trash/restore", "POST", b"x" * (65 * 1024))[0]
        except ConnectionError:
            status = 413
        self.assertEqual(status, 413)
        self.assertEqual(FakeTidemark.seen, [])


@unittest.skipUnless(shutil.which("php"), "php not installed")
class PhpBackend(Backend, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = free_port()
        cls.proc = start(["php", "-S", f"127.0.0.1:{cls.port}", "admin-ui/server.php"], cls.port,
                         dict(ENV, TIDEMARK_UI_PORT=str(cls.port)))

    @classmethod
    def tearDownClass(cls):
        cls.proc.kill()
        cls.proc.wait()


if __name__ == "__main__":
    unittest.main(verbosity=1)
