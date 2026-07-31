"""abuse.ch ThreatFox - IOC/zararli yazilim ailesi eslesmesi. Anahtar gerekmez."""
from __future__ import annotations

import json
import urllib.request

from ..http import USER_AGENT, HttpError
from .base import Provider, ProviderResult

API = "https://threatfox-api.abuse.ch/api/v1/"


class ThreatFox(Provider):
    name = "ThreatFox"
    requires_key = False
    site = "https://threatfox.abuse.ch"
    supports = ("url", "domain", "ipv4", "md5", "sha256")
    min_interval = 0.3

    def _query(self, indicator: str, ioc_type: str) -> ProviderResult:
        body = json.dumps({"query": "search_ioc", "search_term": indicator}).encode()
        request = urllib.request.Request(
            API, data=body,
            headers={"User-Agent": USER_AGENT, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                data = json.loads(response.read().decode("utf-8", "replace"))
        except Exception as exc:
            raise HttpError(str(exc))

        if data.get("query_status") != "ok" or not data.get("data"):
            return ProviderResult(self.name, indicator, found=False,
                                  detail="kayit bulunamadi",
                                  link=f"{self.site}/browse/")

        entries = data["data"]
        first = entries[0]
        labels = []
        if first.get("malware_printable"):
            labels.append(first["malware_printable"])
        if first.get("threat_type"):
            labels.append(first["threat_type"])
        for tag in (first.get("tags") or [])[:4]:
            labels.append(tag)

        confidence = int(first.get("confidence_level") or 75)
        return ProviderResult(
            provider=self.name, indicator=indicator, found=True, malicious=True,
            score=max(confidence, 75), labels=list(dict.fromkeys(labels))[:6],
            detail=(f"{len(entries)} kayit, ilk goruldu: "
                    f"{first.get('first_seen', '?')}, guven: %{confidence}"),
            link=f"{self.site}/ioc/{first.get('id', '')}",
            raw={"malware": first.get("malware_printable"),
                 "threat_type": first.get("threat_type"),
                 "entry_count": len(entries)},
        )
