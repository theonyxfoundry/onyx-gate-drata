"""A minimal Drata Public API v2 client — standard library only.

Covers exactly the two calls the evidence bridge needs, per Drata's published
OpenAPI specification (developers.drata.com, API v2):

* ``POST /workspaces/{workspaceId}/evidence-files`` — upload one artifact file
  (multipart), returning its ``fileKey``.
* ``POST /workspaces/{workspaceId}/evidence`` — create an Evidence item from
  uploaded artifacts, optionally linked to controls (``controlIds``).

Auth is a bearer API key (created in Drata with granular per-endpoint write
scopes — this client needs only the evidence-post scope). Regional bases:
US ``public-api.drata.com``, EU ``public-api.eu.drata.com``, APAC
``public-api.apac.drata.com``.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
import uuid
from typing import Any, Optional

REGION_BASES = {
    "us": "https://public-api.drata.com/public/v2",
    "eu": "https://public-api.eu.drata.com/public/v2",
    "apac": "https://public-api.apac.drata.com/public/v2",
}


class DrataError(Exception):
    """The Drata API could not be reached or refused the request."""


def _encode_multipart(filename: str, content: bytes, mime: str) -> tuple[bytes, str]:
    """Encode one file as multipart/form-data field ``file``."""
    boundary = "onyxgate" + uuid.uuid4().hex
    head = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: {mime}\r\n\r\n"
    ).encode("utf-8")
    tail = f"\r\n--{boundary}--\r\n".encode("utf-8")
    return head + content + tail, f"multipart/form-data; boundary={boundary}"


class DrataClient:
    def __init__(
        self,
        api_key: str,
        region: str = "us",
        base_url: Optional[str] = None,
        timeout: float = 60.0,
    ) -> None:
        if not api_key:
            raise DrataError("a Drata API key is required")
        if base_url is None:
            try:
                base_url = REGION_BASES[region]
            except KeyError:
                raise DrataError(f"unknown region {region!r} (us, eu, apac)") from None
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def _request(self, method: str, path: str, body: bytes, content_type: str) -> dict:
        req = urllib.request.Request(
            self.base_url + path,
            data=body,
            method=method,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": content_type,
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            detail = ""
            try:
                detail = e.read().decode("utf-8", "replace")[:500]
            except Exception:
                pass
            raise DrataError(f"Drata API returned HTTP {e.code} for {path}: {detail}") from e
        except urllib.error.URLError as e:
            raise DrataError(f"Drata API unreachable at {self.base_url}: {e.reason}") from e
        except (TimeoutError, OSError, ValueError) as e:
            raise DrataError(f"Drata API request failed: {e}") from e

    def upload_evidence_file(
        self, workspace_id: int, filename: str, content: bytes, mime: str
    ) -> str:
        """Upload one artifact file; returns the ``fileKey`` to reference."""
        body, content_type = _encode_multipart(filename, content, mime)
        resp = self._request(
            "POST", f"/workspaces/{workspace_id}/evidence-files", body, content_type
        )
        file_key = resp.get("fileKey")
        if not file_key:
            raise DrataError(f"upload response carried no fileKey: {resp!r}")
        return file_key

    def create_evidence(
        self,
        workspace_id: int,
        name: str,
        description: str,
        artifacts: list[dict[str, Any]],
        control_ids: Optional[list[int]] = None,
    ) -> dict:
        """Create an Evidence item from uploaded artifacts."""
        payload: dict[str, Any] = {
            "name": name,
            "description": description,
            "artifacts": artifacts,
        }
        if control_ids:
            payload["controlIds"] = control_ids
        return self._request(
            "POST",
            f"/workspaces/{workspace_id}/evidence",
            json.dumps(payload).encode("utf-8"),
            "application/json",
        )
