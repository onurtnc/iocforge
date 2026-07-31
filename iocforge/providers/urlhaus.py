"""abuse.ch URLhaus - kotu amacli URL/host/payload veritabani. API anahtari gerekmez."""
from __future__ import annotations

from ..http import post_json
from .base import Provider, ProviderResult


class URLhaus(Provider):
    name = "URLhaus"
    requires_key = False
    site = "https://urlhaus.abuse.ch"
    supports = ("url", "domain", "ipv4", "md5", "sha256")
    min_interval = 0.3

    def _query(self, indicator: str, ioc_type: str) -> ProviderResult:
        if ioc_type == "url":
            endpoint, payload = "url", {"url": indicator}
        elif ioc_type in ("md5", "sha256"):
            endpoint = "payload"
            payload = {"md5_hash" if ioc_type == "md5" else "sha256_hash": indicator}
        else:
            endpoint, payload = "host", {"host": indicator}

        data = post_json(f"https://urlhaus-api.abuse.ch/v1/{endpoint}/", payload,
                         rate_key="urlhaus", min_interval=self.min_interval)
        status = data.get("query_status")
        if status != "ok":
            return ProviderResult(self.name, indicator, found=False,
                                  detail="kayit bulunamadi",
                                  link=f"{self.site}/browse.php?search={indicator}")

        labels = list(dict.fromkeys(data.get("tags") or []))[:6]
        if data.get("signature"):
            labels.insert(0, str(data["signature"]))
        if data.get("file_type"):
            labels.append(str(data["file_type"]))

        urls = data.get("urls") or []
        online = sum(1 for u in urls if u.get("url_status") == "online")
        threat = data.get("threat") or (urls[0].get("threat") if urls else "")
        detail_parts = []
        if threat:
            detail_parts.append(str(threat))
        if urls:
            detail_parts.append(f"{len(urls)} kayitli URL ({online} aktif)")
        if data.get("url_status"):
            detail_parts.append(f"durum: {data['url_status']}")
        if data.get("firstseen") or data.get("first_seen"):
            detail_parts.append(f"ilk goruldu: {data.get('firstseen') or data['first_seen']}")

        return ProviderResult(
            provider=self.name, indicator=indicator, found=True, malicious=True,
            score=90 if online or data.get("url_status") == "online" else 70,
            labels=labels,
            detail=", ".join(detail_parts) or "URLhaus'ta kayitli",
            link=data.get("urlhaus_reference")
                 or f"{self.site}/browse.php?search={indicator}",
            raw={"threat": threat, "url_count": len(urls), "online": online},
        )
