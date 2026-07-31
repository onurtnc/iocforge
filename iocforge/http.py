"""Tek noktadan HTTP istemcisi: hiz siniri, yeniden deneme, test icin degistirilebilir."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from typing import Any, Dict, Optional

USER_AGENT = "IOCForge/1.0 (+https://github.com/topics/threat-intelligence)"

_last_call: Dict[str, float] = defaultdict(float)


class HttpError(RuntimeError):
    def __init__(self, message: str, status: int = 0):
        super().__init__(message)
        self.status = status


def _throttle(key: str, min_interval: float) -> None:
    if min_interval <= 0:
        return
    elapsed = time.time() - _last_call[key]
    if elapsed < min_interval:
        time.sleep(min_interval - elapsed)
    _last_call[key] = time.time()


def get_json(url: str, headers: Optional[Dict[str, str]] = None,
             params: Optional[Dict[str, str]] = None,
             timeout: float = 15.0, rate_key: str = "",
             min_interval: float = 0.0, retries: int = 2) -> Any:
    """GET yapip JSON dondurur. Ag hatalarinda HttpError firlatir."""
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"
    request_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    request_headers.update(headers or {})

    last_error: Optional[Exception] = None
    for attempt in range(retries + 1):
        _throttle(rate_key or url.split("/")[2], min_interval)
        request = urllib.request.Request(url, headers=request_headers)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read().decode("utf-8", "replace")
            return json.loads(body) if body.strip() else {}
        except urllib.error.HTTPError as exc:
            if exc.code in (429, 500, 502, 503, 504) and attempt < retries:
                time.sleep(2 ** attempt)
                last_error = exc
                continue
            detail = ""
            try:
                detail = exc.read().decode("utf-8", "replace")[:200]
            except Exception:
                pass
            raise HttpError(f"HTTP {exc.code}: {exc.reason} {detail}".strip(), exc.code)
        except urllib.error.URLError as exc:
            last_error = exc
            if attempt < retries:
                time.sleep(1 + attempt)
                continue
            raise HttpError(f"baglanti hatasi: {exc.reason}")
        except json.JSONDecodeError as exc:
            raise HttpError(f"gecersiz JSON yaniti: {exc}")
    raise HttpError(f"istek basarisiz: {last_error}")


def post_json(url: str, data: Dict[str, str],
              headers: Optional[Dict[str, str]] = None,
              timeout: float = 15.0, rate_key: str = "",
              min_interval: float = 0.0) -> Any:
    request_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    request_headers.update(headers or {})
    payload = urllib.parse.urlencode(data).encode()
    _throttle(rate_key or url.split("/")[2], min_interval)
    request = urllib.request.Request(url, data=payload, headers=request_headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", "replace")
        return json.loads(body) if body.strip() else {}
    except urllib.error.HTTPError as exc:
        raise HttpError(f"HTTP {exc.code}: {exc.reason}", exc.code)
    except urllib.error.URLError as exc:
        raise HttpError(f"baglanti hatasi: {exc.reason}")
    except json.JSONDecodeError as exc:
        raise HttpError(f"gecersiz JSON yaniti: {exc}")
