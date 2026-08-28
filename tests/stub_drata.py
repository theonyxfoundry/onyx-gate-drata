"""A canned Drata Public API v2 stub for the test suite ONLY — speaks the
evidence-files upload and evidence create shapes so the client/CLI can be
exercised without a Drata workspace."""

from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


class StubDrata:
    def __init__(self, api_key: str = "test-key") -> None:
        self.api_key = api_key
        self.uploads: list[dict] = []
        self.evidence: list[dict] = []
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def _json(self, status: int, body: dict) -> None:
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                if self.headers.get("Authorization") != f"Bearer {stub.api_key}":
                    self._json(401, {"statusCode": 401, "message": "Unauthorized"})
                    return
                m = re.fullmatch(r"/workspaces/(\d+)/evidence-files", self.path)
                if m:
                    filename = "?"
                    fm = re.search(rb'filename="([^"]+)"', body)
                    if fm:
                        filename = fm.group(1).decode()
                    key = f"acct/evidence-library/{len(stub.uploads) + 1}/{filename}"
                    stub.uploads.append(
                        {"workspace": int(m.group(1)), "filename": filename, "body": body, "fileKey": key}
                    )
                    self._json(
                        201,
                        {"fileKey": key, "originalFilename": filename, "mimeType": "x", "fileSize": len(body)},
                    )
                    return
                m = re.fullmatch(r"/workspaces/(\d+)/evidence", self.path)
                if m:
                    payload = json.loads(body)
                    payload["_workspace"] = int(m.group(1))
                    stub.evidence.append(payload)
                    self._json(201, {"id": 4242, "name": payload.get("name")})
                    return
                self._json(404, {"statusCode": 404, "message": "Not Found"})

            def log_message(self, *args: object) -> None:
                pass

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def __enter__(self) -> "StubDrata":
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)
